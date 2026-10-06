// Package probe runs the network measurements behind dpiprisma's verdicts.
package probe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"

	"github.com/miekg/dns"
)

// ErrNXDomain reports that the domain does not exist.
var ErrNXDomain = errors.New("probe: domain does not exist")

// Resolver looks up the IPv4 addresses of a host.
type Resolver interface {
	LookupA(ctx context.Context, host string) ([]netip.Addr, error)
}

// DoHResolver resolves names with DNS over HTTPS (RFC 8484).
type DoHResolver struct {
	URL    string       // DoH endpoint, e.g. "https://cloudflare-dns.com/dns-query"
	Client *http.Client // HTTP client used for the queries
}

// SystemResolver resolves names with the operating system's DNS settings,
// which the ISP usually controls.
type SystemResolver struct{}

// LookupA returns the A records of host, asked through the DoH server.
func (r *DoHResolver) LookupA(ctx context.Context, host string) ([]netip.Addr, error) {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(host), dns.TypeA)
	query.Id = 0
	wire, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("probe: pack query for %s: %w", host, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL, bytes.NewReader(wire))

	if err != nil {
		return nil, fmt.Errorf("probe: build DoH request: %w", err)
	}

	req.Header.Set("Content-Type", "application/dns-message")

	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("probe: DoH request to %s: %w", r.URL, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("probe: DoH server %s returned %s", r.URL, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // never read more than 64 KiB
	if err != nil {
		return nil, fmt.Errorf("probe: read DoH response: %w", err)
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, fmt.Errorf("probe: unpack DoH response: %w", err)
	}
	if reply.Rcode == dns.RcodeNameError {
		return nil, ErrNXDomain
	}
	if reply.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("probe: DoH server answered %s", dns.RcodeToString[reply.Rcode])
	}

	var addrs []netip.Addr

	for _, rr := range reply.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		if addr, ok := netip.AddrFromSlice(a.A.To4()); ok {
			addrs = append(addrs, addr)
		}
	}

	return addrs, nil

}

// LookupA returns the A records of host from the system resolver.
func (s *SystemResolver) LookupA(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, ErrNXDomain
		}
		return nil, fmt.Errorf("probe: system lookup %s: %w", host, err)
	}
	return addrs, nil
}

// DNSComparison is the result of asking the system resolver and a trusted
// resolver for the same host.
type DNSComparison struct {
	System   []netip.Addr // the system resolver's answer; empty if it said NXDOMAIN
	Trusted  []netip.Addr // the trusted (DoH) resolver's answer
	Mismatch bool         // the two answers share no address
	Bogus    bool         // the system answered with a private, loopback or unspecified address
}

// CompareDNS looks up host with both resolvers and reports whether the
// system answer looks tampered with. A system NXDOMAIN is a finding, not an
// error; any other failure of either resolver is returned.
func CompareDNS(ctx context.Context, system, trusted Resolver, host string) (DNSComparison, error) {
	var dc DNSComparison

	trustedAddrs, err := trusted.LookupA(ctx, host)
	if err != nil {
		return dc, err
	}
	dc.Trusted = trustedAddrs

	systemAddrs, err := system.LookupA(ctx, host)
	if err != nil && !errors.Is(err, ErrNXDomain) {
		return dc, err
	}
	dc.System = systemAddrs

	dc.Mismatch = true
	for _, addr := range dc.System {
		if slices.Contains(dc.Trusted, addr) {
			dc.Mismatch = false
			break
		}
	}

	for _, addr := range dc.System {
		if addr.IsPrivate() || addr.IsLoopback() || addr.IsUnspecified() {
			dc.Bogus = true
		}
	}

	return dc, nil
}
