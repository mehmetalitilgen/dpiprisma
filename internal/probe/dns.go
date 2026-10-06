package probe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"

	"github.com/miekg/dns"
)

// ErrNXDomain reports that the domain does not exist.
var ErrNXDomain = errors.New("probe: domain does not exist")

// Resolver looks up the IPv4 addresses of a host.
type Resolver interface {
	LookupA(ctx context.Context, host string) ([]netip.Addr, error)
}

type DoHResolver struct {
	URL    string
	Client *http.Client
}

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
