# dpiprisma

[![CI](https://github.com/mehmetalitilgen/dpiprisma/actions/workflows/ci.yml/badge.svg)](https://github.com/mehmetalitilgen/dpiprisma/actions/workflows/ci.yml)

Give it a domain and dpiprisma tells you **how** it is blocked on your network,
**where** the DPI device sits, and **which** circumvention parameters actually
work — in a readable report.

> **Status:** diagnosis (`dpiprisma scan`), locating the DPI device
> (`dpiprisma locate`) and reports (`dpiprisma report`) work. Forged-reset
> detection is implemented as a library and needs root; the strategy matrix
> command is in progress.

## What it does

- **Diagnose** *(available)* — tells DNS poisoning, IP-level blackholing and SNI-based
  blocking apart using controlled A/B tests: same IP, same port, only the SNI
  changes. A system DNS answer that differs from DNS over HTTPS is checked by
  a full TLS handshake: a CDN node holds a certificate for the domain, an ISP
  block page cannot.
- **Locate** *(available)* — finds how many hops away the DPI device is by
  sending TLS ClientHello messages with increasing TTL values, and how far the
  real server is, which gives the TTL range a decoy packet can use.
- **Detect forged resets** *(library, needs root)* — spots injected TCP RST
  packets by comparing their TTL and IP-ID with genuine packets from the
  server.
- **Test strategies** — runs a matrix of evasion techniques (split, disorder,
  fake ClientHello, …) and measures the success rate and latency of each.
- **Report** *(available)* — turns saved results into a Markdown or HTML
  report, with the strategy matrix as a heat map and ready-to-use commands for
  gecit, zapret, GoodbyeDPI and byedpi.

Those tools are the medicine; dpiprisma is the diagnosis that tells you the
right dose.

## Install

Download the archive for your system from the
[releases page](https://github.com/mehmetalitilgen/dpiprisma/releases): Linux,
Windows and macOS, each for amd64 and arm64. Each archive holds a single
binary with no dependencies.

To build from source instead (Go 1.25 or newer):

```sh
go build ./cmd/dpiprisma
```

## Usage

```console
$ dpiprisma scan example.com github.com
DOMAIN       VERDICT     REASON
example.com  accessible  TLS handshake succeeded
github.com   accessible  TLS handshake succeeded
```

For each domain, `scan` compares the system DNS answer with DNS over HTTPS,
opens a TCP connection to the real address and sends two TLS ClientHellos to
it — one with a harmless control name, one with the domain — then reports one
of `accessible`, `dns_poisoning`, `ip_blackhole`, `sni_blocking` or
`unknown`, with the reason.

| Flag | Default | Meaning |
|---|---|---|
| `--json` | off | Print JSON instead of a table |
| `--timeout` | `5s` | Time limit for each network step |
| `--parallel` | `4` | Domains scanned at the same time (at least 1) |
| `--doh` | Cloudflare | Trusted DNS-over-HTTPS endpoint |
| `-v` | off | Print debug logs for every step (to stderr) |

```console
$ dpiprisma locate blocked.example
probing blocked.example 3 times; this can take a minute or two
target    blocked.example (203.0.113.10:443)
reset     4.4 ms after the ClientHello, handshake 53.8 ms: injected (faster than the server could answer)
dpi       about 3 hops away (3 of 3 runs agree)
server    6-7 hops away
fake-ttl  3-5
```

`locate` first sends a normal ClientHello. If the connection is reset, it
repeats the ClientHello with the IP TTL set to 1, 2, 3, … until the reset
appears; that TTL is the distance to the DPI device. The same walk with a
harmless control name measures the distance to the server. `fake-ttl` is the
range in between: a decoy packet with such a TTL reaches the DPI device but
never the server. `locate` needs no special privileges.

| Flag | Default | Meaning |
|---|---|---|
| `--runs` | `3` | How many times to repeat the search (at least 1) |
| `--timeout` | `2s` | Time limit for each probe |
| `--max-ttl` | `30` | Highest TTL to try (1–255) |
| `--gap` | `100ms` | Pause between probes |
| `--control` | `example.com` | Harmless name used to measure the server's distance |
| `--doh` | Cloudflare | Trusted DNS-over-HTTPS endpoint |
| `--json` | off | Print JSON for `dpiprisma report` instead of text |

Forged-reset detection and the SYN-based path walk read and write raw
sockets. They work on Linux with root (or `CAP_NET_RAW`) and do not run on
Windows; no packet-capture driver is needed.

```console
$ dpiprisma scan --json blocked.example > scan.json
$ dpiprisma locate --json blocked.example > locate.json
$ dpiprisma report --scan scan.json --locate locate.json -o report.html
```

`report` reads the JSON that `scan`, `locate` and `matrix` write with
`--json` and writes one report: the diagnosis, the distance to the DPI device,
the strategy matrix as a heat map of success rates, and for each domain a
ready-to-use command for gecit, zapret, GoodbyeDPI and byedpi, built from the
strategy that worked best. A domain the matrix has not tested gets commands
built from the decoy TTL that `locate` found, marked as untested. The commands
are starting points; each tool's own documentation covers its setup.

| Flag | Default | Meaning |
|---|---|---|
| `--scan` | – | JSON from `scan --json` (repeatable) |
| `--locate` | – | JSON from `locate --json` (repeatable) |
| `--matrix` | – | JSON from `matrix --json` (repeatable) |
| `-o` | stdout | File to write |
| `--format` | from `-o` | `md` or `html`; without it, a `.html` output is HTML, anything else Markdown |

## Releasing

Pushing a version tag builds the binaries for every platform with
[GoReleaser](https://goreleaser.com) and publishes them as a GitHub release:

```sh
git tag v1.0.0
git push origin v1.0.0
```

## Disclaimer

dpiprisma is a network measurement and research tool.

- Run it only on networks and connections you own or are authorized to test.
- Keep traffic minimal. A few connections per test are enough; never use it to
  put load on third-party servers.
- Prefer servers you control or public test domains as targets.
- You are solely responsible for complying with the laws of your jurisdiction.
  The authors accept no liability for misuse of this software or for any
  consequences of its use.

## License

[MIT](LICENSE) © 2026 Mehmet Ali Tilgen
