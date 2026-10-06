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
