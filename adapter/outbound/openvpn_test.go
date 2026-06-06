package outbound

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/miekg/dns"
)

type mockResolver struct {
	mapping map[string]netip.Addr
}

func (m mockResolver) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	if ip, ok := m.mapping[host]; ok {
		return []netip.Addr{ip}, nil
	}
	return nil, resolver.ErrIPNotFound
}

func (m mockResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return m.LookupIP(ctx, host)
}

func (m mockResolver) LookupIPv6(_ context.Context, _ string) ([]netip.Addr, error) {
	return nil, resolver.ErrIPNotFound
}

func (m mockResolver) ResolveECH(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}

func (m mockResolver) ExchangeContext(_ context.Context, _ *dns.Msg) (*dns.Msg, error) {
	return nil, nil
}

func (m mockResolver) Invalid() bool {
	return true
}

func (m mockResolver) ClearCache() {}

func (m mockResolver) ResetConnection() {}

func TestRewriteProfileRemotes(t *testing.T) {
	o := &OpenVPN{
		resolver: mockResolver{
			mapping: map[string]netip.Addr{
				"vpn.example.com": netip.MustParseAddr("203.0.113.10"),
			},
		},
	}
	input := strings.Join([]string{
		"client",
		"remote vpn.example.com 1194 udp",
		"remote 198.51.100.2 443 tcp",
		"remote unresolved.example.com 1194",
		"remote vpn.example.com 443 ; keep comment",
		"",
	}, "\n")
	output, rewritten, failed, err := o.rewriteProfileRemotes(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("rewriteProfileRemotes failed: %v", err)
	}
	if rewritten != 2 {
		t.Fatalf("expected rewritten=2, got=%d", rewritten)
	}
	if failed != 1 {
		t.Fatalf("expected failed=1, got=%d", failed)
	}
	got := string(output)
	if !strings.Contains(got, "remote 203.0.113.10 1194 udp") {
		t.Fatalf("expected resolved remote not found, got:\n%s", got)
	}
	if !strings.Contains(got, "remote 198.51.100.2 443 tcp") {
		t.Fatalf("expected existing ip remote kept, got:\n%s", got)
	}
	if !strings.Contains(got, "remote unresolved.example.com 1194") {
		t.Fatalf("expected unresolved remote kept, got:\n%s", got)
	}
	if !strings.Contains(got, "remote 203.0.113.10 443 ; keep comment") {
		t.Fatalf("expected resolved remote with comment kept, got:\n%s", got)
	}
}

func TestRewriteProfileRemotesPreferProxyServerHostResolver(t *testing.T) {
	originalProxyServerHostResolver := resolver.ProxyServerHostResolver
	defer func() {
		resolver.ProxyServerHostResolver = originalProxyServerHostResolver
	}()

	resolver.ProxyServerHostResolver = mockResolver{
		mapping: map[string]netip.Addr{
			"vpn.example.com": netip.MustParseAddr("203.0.113.99"),
		},
	}

	o := &OpenVPN{
		resolver: mockResolver{
			mapping: map[string]netip.Addr{
				"vpn.example.com": netip.MustParseAddr("203.0.113.10"),
			},
		},
	}

	input := "remote vpn.example.com 1194 udp\n"
	output, rewritten, failed, err := o.rewriteProfileRemotes(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("rewriteProfileRemotes failed: %v", err)
	}
	if rewritten != 1 {
		t.Fatalf("expected rewritten=1, got=%d", rewritten)
	}
	if failed != 0 {
		t.Fatalf("expected failed=0, got=%d", failed)
	}

	got := string(output)
	if !strings.Contains(got, "remote 203.0.113.99 1194 udp") {
		t.Fatalf("expected proxy server resolver result, got:\n%s", got)
	}
}

func TestRewriteProfileRemotesNoRemoteLine(t *testing.T) {
	o := &OpenVPN{}
	input := "client\nproto udp\n"
	output, rewritten, failed, err := o.rewriteProfileRemotes(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("rewriteProfileRemotes failed: %v", err)
	}
	if rewritten != 0 {
		t.Fatalf("expected rewritten=0, got=%d", rewritten)
	}
	if failed != 0 {
		t.Fatalf("expected failed=0, got=%d", failed)
	}
	if string(output) != input {
		t.Fatalf("expected output unchanged, got:\n%s", string(output))
	}
}

func TestResolveUDPFailsClosedWhenVPNDNSUnavailable(t *testing.T) {
	o := &OpenVPN{
		resolver: mockResolver{
			mapping: map[string]netip.Addr{
				"gitlab.shiportlink.com": netip.MustParseAddr("10.31.41.10"),
			},
		},
	}
	metadata := &C.Metadata{
		Host:    "gitlab.shiportlink.com",
		DstPort: 443,
	}

	err := o.ResolveUDP(context.Background(), metadata)
	if err == nil {
		t.Fatal("expected VPN DNS failure, got nil")
	}
	if !strings.Contains(err.Error(), "vpn dns resolve failed") {
		t.Fatalf("expected vpn dns resolve failed error, got: %v", err)
	}
	if metadata.DstIP.IsValid() {
		t.Fatalf("expected destination IP to remain unresolved, got: %s", metadata.DstIP)
	}
}

func TestProbeVPNDNSRequiresConfiguredHost(t *testing.T) {
	o := &OpenVPN{}
	if err := o.probeVPNDNS(context.Background()); err != nil {
		t.Fatalf("expected nil probe result without configured host, got: %v", err)
	}

	o.option = &OpenVPNOption{DNSProbeHost: " gitlab.shiportlink.com "}
	if got := o.dnsProbeHost(); got != "gitlab.shiportlink.com" {
		t.Fatalf("expected trimmed probe host, got: %q", got)
	}
	err := o.probeVPNDNS(context.Background())
	if err == nil {
		t.Fatal("expected probe failure with uninitialized client, got nil")
	}
	if !strings.Contains(err.Error(), "vpn dns probe failed") {
		t.Fatalf("expected vpn dns probe failed error, got: %v", err)
	}
}
