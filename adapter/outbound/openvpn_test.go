package outbound

import (
	"context"
	"net/netip"
	"strings"
	"testing"

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
