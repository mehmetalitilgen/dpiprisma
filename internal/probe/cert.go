package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// CertOutcome is what a full TLS handshake with certificate verification found.
type CertOutcome int

const (
	CertUnknown CertOutcome = iota // the handshake never got as far as the certificate
	CertValid                      // the server holds a certificate valid for the name
	CertInvalid                    // the server's certificate is not valid for the name
)

// certOutcomeNames holds the name of each outcome, in the same order as the constants.
var certOutcomeNames = [...]string{"unknown", "valid", "invalid"}

// String returns the outcome name, e.g. "invalid".
func (c CertOutcome) String() string {
	if c < 0 || int(c) >= len(certOutcomeNames) {
		return fmt.Sprintf("CertOutcome(%d)", int(c))
	}
	return certOutcomeNames[c]
}

// CertResult is the outcome of one certificate check.
type CertResult struct {
	Outcome CertOutcome // what the handshake found
	Err     error       // the handshake error, if any
}

// CertVerifier checks whether the host at an address holds a certificate for
// a name. An ISP that answers DNS with the address of its own block page
// cannot forge such a certificate, so a failed check tells a redirect from a
// CDN node that merely has a different address.
type CertVerifier struct {
	Roots *x509.CertPool // trusted root certificates; nil means the system roots
}

// Verify opens a TCP connection to addr and runs a full TLS handshake for
// serverName within timeout, verifying the certificate chain against
// v.Roots. A chain that does not verify gives CertInvalid; a connection that
// fails before the certificate is seen (refused, reset, timed out) gives
// CertUnknown, since nothing can be said about the host then.
func (v CertVerifier) Verify(ctx context.Context, addr netip.AddrPort, serverName string, timeout time.Duration) CertResult {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName: serverName,
			RootCAs:    v.Roots,
			MinVersion: tls.VersionTLS12,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", addr.String()) // dials and handshakes
	if err == nil {
		conn.Close()
		return CertResult{Outcome: CertValid}
	}

	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return CertResult{Outcome: CertInvalid, Err: err}
	}
	return CertResult{Outcome: CertUnknown, Err: err}
}
