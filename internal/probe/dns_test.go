package probe

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeDoHServer starts a DoH server that answers A queries from answers
// (keyed by fully qualified name, e.g. "example.com.") and NXDOMAIN otherwise.
func fakeDoHServer(t *testing.T, answers map[string][]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query := new(dns.Msg)
		if err := query.Unpack(body); err != nil {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		reply := new(dns.Msg)
		reply.SetReply(query)
		name := query.Question[0].Name
		ips, ok := answers[name]
		if !ok {
			reply.Rcode = dns.RcodeNameError
		}
		for _, ip := range ips {
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(ip),
			})
		}
		wire, _ := reply.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(wire)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDoHResolverLookupA(t *testing.T) {
	srv := fakeDoHServer(t, map[string][]string{
		"example.com.": {"93.184.215.14", "93.184.215.15"},
	})
	r := &DoHResolver{URL: srv.URL, Client: srv.Client()}

	got, err := r.LookupA(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupA error = %v", err)
	}
	want := []netip.Addr{netip.MustParseAddr("93.184.215.14"), netip.MustParseAddr("93.184.215.15")}
	if !slices.Equal(got, want) {
		t.Errorf("LookupA = %v; want %v", got, want)
	}
}

func TestDoHResolverNXDomain(t *testing.T) {
	srv := fakeDoHServer(t, map[string][]string{})
	r := &DoHResolver{URL: srv.URL, Client: srv.Client()}

	_, err := r.LookupA(context.Background(), "nope.invalid")
	if !errors.Is(err, ErrNXDomain) {
		t.Errorf("LookupA error = %v; want ErrNXDomain", err)
	}
}

func TestDoHResolverHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	r := &DoHResolver{URL: srv.URL, Client: srv.Client()}

	if _, err := r.LookupA(context.Background(), "example.com"); err == nil {
		t.Error("LookupA error = nil; want an error for HTTP 500")
	}
}

func TestIntegrationDoHCloudflare(t *testing.T) {
	if os.Getenv("DPIPRISMA_INTEGRATION") == "" {
		t.Skip("set DPIPRISMA_INTEGRATION=1 to run tests that need the internet")
	}
	r := &DoHResolver{
		URL:    "https://cloudflare-dns.com/dns-query",
		Client: &http.Client{Timeout: 5 * time.Second},
	}

	got, err := r.LookupA(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupA error = %v", err)
	}
	if len(got) == 0 {
		t.Error("LookupA returned no addresses")
	}
	t.Logf("example.com -> %v", got)
}

// fakeResolver answers from a fixed map; a missing host gives err (or
// ErrNXDomain when err is nil).
type fakeResolver struct {
	answers map[string][]string
	err     error
}

func (f fakeResolver) LookupA(ctx context.Context, host string) ([]netip.Addr, error) {
	if f.err != nil {
		return nil, f.err
	}
	ips, ok := f.answers[host]
	if !ok {
		return nil, ErrNXDomain
	}
	var addrs []netip.Addr
	for _, ip := range ips {
		addrs = append(addrs, netip.MustParseAddr(ip))
	}
	return addrs, nil
}

func TestCompareDNS(t *testing.T) {
	trusted := fakeResolver{answers: map[string][]string{"x.com": {"1.1.1.1", "2.2.2.2"}}}
	broken := errors.New("network down")

	tests := []struct {
		name         string
		system       Resolver
		trusted      Resolver
		wantMismatch bool
		wantBogus    bool
		wantErr      bool
	}{
		{"same answer", fakeResolver{answers: map[string][]string{"x.com": {"2.2.2.2"}}}, trusted, false, false, false},
		{"different public answer", fakeResolver{answers: map[string][]string{"x.com": {"9.9.9.9"}}}, trusted, true, false, false},
		{"loopback answer", fakeResolver{answers: map[string][]string{"x.com": {"127.0.0.1"}}}, trusted, true, true, false},
		{"private answer", fakeResolver{answers: map[string][]string{"x.com": {"10.0.0.1"}}}, trusted, true, true, false},
		{"unspecified answer", fakeResolver{answers: map[string][]string{"x.com": {"0.0.0.0"}}}, trusted, true, true, false},
		{"system says NXDOMAIN", fakeResolver{answers: map[string][]string{}}, trusted, true, false, false},
		{"system fails", fakeResolver{err: broken}, trusted, false, false, true},
		{"trusted fails", fakeResolver{answers: map[string][]string{"x.com": {"2.2.2.2"}}}, fakeResolver{err: broken}, false, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CompareDNS(context.Background(), tt.system, tt.trusted, "x.com")
			if (err != nil) != tt.wantErr {
				t.Fatalf("CompareDNS error = %v; wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got.Mismatch != tt.wantMismatch || got.Bogus != tt.wantBogus {
				t.Errorf("CompareDNS = %+v; want Mismatch=%v Bogus=%v", got, tt.wantMismatch, tt.wantBogus)
			}
		})
	}
}

func TestIntegrationSystemResolver(t *testing.T) {
	if os.Getenv("DPIPRISMA_INTEGRATION") == "" {
		t.Skip("set DPIPRISMA_INTEGRATION=1 to run tests that need the internet")
	}
	var r SystemResolver

	got, err := r.LookupA(context.Background(), "example.com")
	if err != nil || len(got) == 0 {
		t.Errorf("LookupA(example.com) = (%v, %v); want at least one address", got, err)
	}
	if _, err := r.LookupA(context.Background(), "nope.invalid"); !errors.Is(err, ErrNXDomain) {
		t.Errorf("LookupA(nope.invalid) error = %v; want ErrNXDomain", err)
	}
}
