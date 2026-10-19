# Changelog

All notable changes to dpiprisma are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-19

### Added

- `dpiprisma locate`: finds how many hops away the DPI device sits by sending
  TLS ClientHellos with increasing TTL, measures the distance to the real
  server with a harmless control name, and reports the TTL range a decoy
  packet can use. Needs no special privileges.
- `dpiprisma matrix`: runs every bypass strategy against a domain and scores
  it by success rate and latency (p50, p95). Strategies: `baseline`, `split`,
  `disorder`, `fakech` (fake ClientHello with a low TTL) and `fakerst`
  (spoofed low-TTL RST after the real hello). The fake-packet strategies need
  root on Linux.
- `dpiprisma report`: turns the JSON written by `scan`, `locate` and
  `matrix` into a Markdown or HTML report, with the strategy matrix as a heat
  map and ready-to-use commands for gecit, zapret, GoodbyeDPI and byedpi.
- `--json` output for `locate` and `matrix`, so their results feed the report.
- Forged-reset detection as a library: tells injected TCP RSTs from the
  server's own by TTL and IP-ID (`internal/probe`). Raw sockets, Linux only.
- Raw-packet helpers: IPv4/TCP header parsing, internet checksum, raw-socket
  capture and a TTL walk with TCP SYNs (`internal/packet`, `internal/locate`).
- Release pipeline: pushing a `v*` tag builds binaries for Linux, Windows and
  macOS (amd64 and arm64) with GoReleaser and publishes them as a GitHub
  release with checksums.

### Fixed

- `scan --parallel 0` no longer deadlocks; the flag now requires at least 1.
- Probes use tighter timeouts and clearer error reasons.

## [0.1.0] - 2026-10-07

### Added

- `dpiprisma scan`: tells DNS poisoning, IP-level blackholing and SNI-based
  blocking apart with controlled A/B tests. Compares the system DNS answer
  with DNS over HTTPS, checks a differing answer with a full TLS handshake
  and certificate validation, then sends two ClientHellos to the real address,
  one with a control name and one with the domain.
- Verdicts `accessible`, `dns_poisoning`, `ip_blackhole`, `sni_blocking` and
  `unknown`, each with a reason; table and `--json` output.
- Hand-built TLS 1.3 ClientHello and a bounds-checked SNI parser with a fuzz
  test (`internal/tlsx`).
- Cobra command tree, `version` command, `--verbose` logging with `slog`.
- GitHub Actions CI: gofmt, go vet, go test with the race detector, staticcheck.
- MIT license.

[1.0.0]: https://github.com/mehmetalitilgen/dpiprisma/releases/tag/v1.0.0
[0.1.0]: https://github.com/mehmetalitilgen/dpiprisma/releases/tag/v0.1.0
