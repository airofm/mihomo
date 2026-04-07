package outbound

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	openvpn "github.com/airofm/sing-openvpn"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type OpenVPN struct {
	*Base
	option   *OpenVPNOption
	client   *openvpn.Client
	clientMu sync.Mutex // protects client init and reconnect
	resolver resolver.Resolver
}

type OpenVPNOption struct {
	BasicOption
	Name     string `proxy:"name"`
	UserName string `proxy:"username,omitempty"`
	Password string `proxy:"password,omitempty"`
	Profile  string `proxy:"profile"`
}

type ovpnNetDialer struct {
	client *openvpn.Client
}

func (d ovpnNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.client.DialContext(ctx, network, address)
}

// ensureClient returns an alive client, reconnecting if needed.
func (o *OpenVPN) ensureClient(ctx context.Context) (*openvpn.Client, error) {
	o.clientMu.Lock()
	defer o.clientMu.Unlock()

	if o.client != nil && o.client.IsAlive() {
		return o.client, nil
	}

	// Client is nil or dead, need to (re)initialize
	if o.client != nil {
		log.Infoln("[OpenVPN](%s) connection dead, reconnecting...", o.proxyName())
		o.client.Close()
		o.client = nil
	}

	if err := o.initClientLocked(ctx); err != nil {
		return nil, err
	}
	return o.client, nil
}

// DialContext implements C.ProxyAdapter
func (o *OpenVPN) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	client, err := o.ensureClient(ctx)
	if err != nil {
		return nil, err
	}

	if !metadata.Resolved() && metadata.Host != "" {
		if ip, err := o.resolveIPViaVPNDNS(ctx, metadata.Host); err == nil {
			metadata.DstIP = ip
		} else {
			log.Debugln("[OpenVPN](%s) vpn dns resolve failed for tcp host %s: %v", o.proxyName(), metadata.Host, err)
		}
	}

	var conn net.Conn
	targetAddress := metadata.RemoteAddress()
	if metadata.DstIP.IsValid() {
		targetAddress = net.JoinHostPort(metadata.DstIP.String(), strconv.FormatUint(uint64(metadata.DstPort), 10))
	}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer dialCancel()
	if !metadata.Resolved() || o.resolver != nil {
		r := resolver.DefaultResolver
		if o.resolver != nil {
			r = o.resolver
		}
		options := o.DialOptions()
		options = append(options, dialer.WithResolver(r))
		options = append(options, dialer.WithNetDialer(ovpnNetDialer{client: client}))
		conn, err = dialer.NewDialer(options...).DialContext(dialCtx, "tcp", targetAddress)
	} else {
		conn, err = client.DialContext(dialCtx, "tcp", targetAddress)
	}

	if err != nil {
		return nil, err
	}
	return NewConn(conn, o), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (o *OpenVPN) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	client, err := o.ensureClient(ctx)
	if err != nil {
		return nil, err
	}

	if err := o.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	targetAddress := metadata.RemoteAddress()
	if metadata.DstIP.IsValid() {
		targetAddress = net.JoinHostPort(metadata.DstIP.String(), strconv.FormatUint(uint64(metadata.DstPort), 10))
	}
	packetCtx, packetCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer packetCancel()
	pc, err := client.ListenPacket(packetCtx, targetAddress)
	if err != nil {
		return nil, err
	}
	return newPacketConn(pc, o), nil
}

func (o *OpenVPN) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if (!metadata.Resolved() || o.resolver != nil) && metadata.Host != "" {
		if ip, err := o.resolveIPViaVPNDNS(ctx, metadata.Host); err == nil {
			metadata.DstIP = ip
			return nil
		} else {
			log.Debugln("[OpenVPN](%s) vpn dns resolve failed for udp host %s: %v", o.proxyName(), metadata.Host, err)
		}
		r := resolver.DefaultResolver
		if o.resolver != nil {
			r = o.resolver
		}
		ip, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, r)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

func (o *OpenVPN) resolveIPViaVPNDNS(ctx context.Context, host string) (netip.Addr, error) {
	if o.client == nil {
		return netip.Addr{}, fmt.Errorf("openvpn client not initialized")
	}
	dnsServer := "8.8.8.8:53"
	if cfg := o.client.GetConfig(); len(cfg.DNS) > 0 {
		dnsServer = net.JoinHostPort(cfg.DNS[0], "53")
	}
	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return o.client.DialContext(ctx, "udp", dnsServer)
		},
	}
	var lastErr error
	for range 3 {
		if err := ctx.Err(); err != nil {
			return netip.Addr{}, err
		}
		lookupCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		// Use "ip4" network to only send A queries, avoiding AAAA queries that
		// get silently dropped by VPN servers with block-ipv6, which would cause
		// a ~5 second timeout waiting for the AAAA response.
		ips, err := res.LookupIP(lookupCtx, "ip4", host)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if len(ips) == 0 {
			lastErr = fmt.Errorf("can't resolve ip for %s", host)
			continue
		}
		ip, ok := netip.AddrFromSlice(ips[0])
		if !ok {
			lastErr = fmt.Errorf("can't parse resolved ip for %s", host)
			continue
		}
		return ip.Unmap(), nil
	}
	return netip.Addr{}, lastErr
}

func (o *OpenVPN) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

// initClientLocked creates and connects a new OpenVPN client.
// Must be called with o.clientMu held.
func (o *OpenVPN) initClientLocked(ctx context.Context) error {
	initStart := time.Now()
	log.Infoln("[OpenVPN](%s) initClient started", o.proxyName())
	var ovpnContent []byte

	if o.option.Profile != "" {
		if C.Path.Resolve(o.option.Profile) == "" {
			return fmt.Errorf("profile path not found: %s", o.option.Profile)
		}

		content, err := os.ReadFile(C.Path.Resolve(o.option.Profile))
		if err != nil {
			return fmt.Errorf("failed to read profile file: %w", err)
		}
		ovpnContent = content
	} else {
		return fmt.Errorf("profile must be provided for openvpn")
	}
	resolveCtx, resolveCancel := context.WithTimeout(ctx, 10*time.Second)
	defer resolveCancel()
	ovpnContent, rewritten, failed, err := o.rewriteProfileRemotes(resolveCtx, ovpnContent)
	if err != nil {
		return err
	}
	if rewritten > 0 || failed > 0 {
		log.Debugln("[OpenVPN](%s) profile remote rewrite summary: rewritten=%d failed=%d resolver=%s", o.proxyName(), rewritten, failed, o.profileRemoteResolverName())
	}
	if failed > 0 {
		return fmt.Errorf("openvpn profile remote resolve failed: failed=%d resolver=%s", failed, o.profileRemoteResolverName())
	}

	client, err := openvpn.NewClient(ovpnContent, o.option.UserName, o.option.Password, o.dialer)
	if err != nil {
		return err
	}

	// Register onClose callback: when the VPN connection dies,
	// log it so next request triggers reconnection via ensureClient.
	client.SetOnClose(func() {
		log.Warnln("[OpenVPN](%s) VPN connection closed, will reconnect on next request", o.proxyName())
	})

	// Use a dedicated context with generous timeout for VPN connection establishment,
	// not the request context which may have a short deadline.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer dialCancel()
	if err := client.Dial(dialCtx); err != nil {
		return err
	}
	o.client = client
	log.Infoln("[OpenVPN](%s) VPN client connected successfully, total init time: %s", o.proxyName(), time.Since(initStart))
	return nil
}

func (o *OpenVPN) rewriteProfileRemotes(ctx context.Context, content []byte) ([]byte, int, int, error) {
	r := o.profileRemoteResolver()
	cache := map[string]string{}
	rewritten := 0
	failed := 0
	var out bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			out.WriteString(rawLine)
			out.WriteByte('\n')
			continue
		}
		lineNoComment := trimmed
		commentSuffix := ""
		if idx := strings.IndexAny(lineNoComment, "#;"); idx != -1 {
			commentSuffix = strings.TrimSpace(lineNoComment[idx:])
			lineNoComment = strings.TrimSpace(lineNoComment[:idx])
		}
		fields := strings.Fields(lineNoComment)
		if len(fields) < 2 || fields[0] != "remote" {
			out.WriteString(rawLine)
			out.WriteByte('\n')
			continue
		}
		host := fields[1]
		if _, err := netip.ParseAddr(host); err == nil {
			out.WriteString(rawLine)
			out.WriteByte('\n')
			continue
		}
		resolved := cache[host]
		if resolved == "" {
			var (
				ip  netip.Addr
				err error
			)
			for range 3 {
				ip, err = resolver.ResolveIPWithResolver(ctx, host, r)
				if err == nil {
					break
				}
			}
			if err != nil {
				failed++
				log.Debugln("[OpenVPN](%s) profile remote resolve failed: host=%s resolver=%s err=%v", o.proxyName(), host, o.profileRemoteResolverName(), err)
				out.WriteString(rawLine)
				out.WriteByte('\n')
				continue
			}
			resolved = ip.String()
			cache[host] = resolved
			log.Debugln("[OpenVPN](%s) profile remote resolved: host=%s ip=%s resolver=%s", o.proxyName(), host, resolved, o.profileRemoteResolverName())
		} else {
			log.Debugln("[OpenVPN](%s) profile remote resolved from cache: host=%s ip=%s", o.proxyName(), host, resolved)
		}
		fields[1] = resolved
		line := strings.Join(fields, " ")
		if commentSuffix != "" {
			line += " " + commentSuffix
		}
		rewritten++
		out.WriteString(line)
		out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, rewritten, failed, err
	}
	return out.Bytes(), rewritten, failed, nil
}

func (o *OpenVPN) profileRemoteResolver() resolver.Resolver {
	if resolver.ProxyServerHostResolver != nil {
		return resolver.ProxyServerHostResolver
	}
	if o.resolver != nil {
		return o.resolver
	}
	return resolver.DefaultResolver
}

func (o *OpenVPN) profileRemoteResolverName() string {
	if resolver.ProxyServerHostResolver != nil {
		return "ProxyServerHostResolver"
	}
	if o.resolver != nil {
		return "OutboundResolver"
	}
	return "DefaultResolver"
}

func (o *OpenVPN) proxyName() string {
	if o.option != nil && o.option.Name != "" {
		return o.option.Name
	}
	return "openvpn"
}

// SupportUDP implements C.ProxyAdapter
func (o *OpenVPN) SupportUDP() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (o *OpenVPN) ProxyInfo() C.ProxyInfo {
	return C.ProxyInfo{
		ProviderName: o.Base.pdName,
	}
}

// Close implements C.ProxyAdapter
func (o *OpenVPN) Close() error {
	o.clientMu.Lock()
	defer o.clientMu.Unlock()
	if o.client != nil {
		err := o.client.Close()
		o.client = nil
		return err
	}
	return nil
}

func (o *OpenVPN) DialOptions() []dialer.Option {
	return []dialer.Option{
		dialer.WithInterface(o.iface),
		dialer.WithRoutingMark(o.rmark),
		dialer.WithTFO(o.tfo),
	}
}

// PreConnect proactively establishes the OpenVPN tunnel in the background,
// so the first user request does not have to wait for the full handshake.
func (o *OpenVPN) PreConnect() {
	go func() {
		log.Infoln("[OpenVPN](%s) pre-connecting VPN tunnel in background...", o.proxyName())
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := o.ensureClient(ctx); err != nil {
			log.Warnln("[OpenVPN](%s) pre-connect failed: %v (will retry on first request)", o.proxyName(), err)
		} else {
			log.Infoln("[OpenVPN](%s) pre-connect succeeded, tunnel is ready", o.proxyName())
		}
	}()
}

func NewOpenVPN(option OpenVPNOption) (*OpenVPN, error) {
	outbound := &OpenVPN{
		Base: &Base{
			name:   option.Name,
			tp:     C.OpenVPN,
			pdName: option.ProviderName,
		},
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())

	return outbound, nil
}
