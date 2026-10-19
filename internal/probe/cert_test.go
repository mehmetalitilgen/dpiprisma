package probe

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestCertOutcomeString(t *testing.T) {
	tests := []struct {
		c    CertOutcome
		want string
	}{
		{CertUnknown, "unknown"},
		{CertValid, "valid"},
		{CertInvalid, "invalid"},
		{CertOutcome(7), "CertOutcome(7)"},
		{CertOutcome(-1), "CertOutcome(-1)"},
	}
	for _, tt := range tests {
		if got := tt.c.String(); got != tt.want {
			t.Errorf("CertOutcome(%d).String() = %q, want %q", int(tt.c), got, tt.want)
		}
	}
}

// tlsServer starts a TLS server with the self-signed certificate of httptest,
// which is valid for example.com and 127.0.0.1, and returns its address and a
// root pool that trusts it.
func tlsServer(t *testing.T) (netip.AddrPort, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return netip.MustParseAddrPort(srv.Listener.Addr().String()), roots
}

func TestCertVerifierVerify(t *testing.T) {
	addr, roots := tlsServer(t)

	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := netip.MustParseAddrPort(closedLn.Addr().String())
	closedLn.Close()

	tests := []struct {
		name    string
		addr    netip.AddrPort
		sni     string
		roots   *x509.CertPool
		want    CertOutcome
		wantErr bool
	}{
		{"valid for the name", addr, "example.com", roots, CertValid, false},
		{"certificate is for another name", addr, "blocked.example", roots, CertInvalid, true},
		{"unknown authority", addr, "example.com", nil, CertInvalid, true},
		{"connection refused", closed, "example.com", roots, CertUnknown, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := CertVerifier{Roots: tt.roots}
			got := v.Verify(context.Background(), tt.addr, tt.sni, 2*time.Second)
			if got.Outcome != tt.want || (got.Err != nil) != tt.wantErr {
				t.Errorf("Verify = (%v, %v); want outcome %v, error %v", got.Outcome, got.Err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestCertVerifierCancelled(t *testing.T) {
	addr, roots := tlsServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := CertVerifier{Roots: roots}.Verify(ctx, addr, "example.com", 2*time.Second)
	if got.Outcome != CertUnknown || got.Err == nil {
		t.Errorf("Verify with a cancelled context = (%v, %v); want unknown with an error", got.Outcome, got.Err)
	}
}
