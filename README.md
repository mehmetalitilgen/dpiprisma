# dpiprisma

[![CI](https://github.com/mehmetalitilgen/dpiprisma/actions/workflows/ci.yml/badge.svg)](https://github.com/mehmetalitilgen/dpiprisma/actions/workflows/ci.yml)

Give it a domain and dpiprisma tells you **how** it is blocked on your network,
**where** the DPI device sits, and **which** circumvention parameters actually
work — in a readable report.

> **Status: v0.1.0.** Diagnosis (`dpiprisma scan`) works. Locating the DPI
> device, forged-reset detection, strategy testing and reports are planned.

## What it does

- **Diagnose** *(available)* — tells DNS poisoning, IP-level blackholing and SNI-based
  blocking apart using controlled A/B tests: same IP, same port, only the SNI
  changes.
- **Locate** — finds how many hops away the DPI device is by sending TLS
  ClientHello messages with increasing TTL values.
- **Detect forged resets** — spots injected TCP RST packets by comparing their
  TTL and IP-ID with genuine packets from the server.
- **Test strategies** — runs a matrix of evasion techniques (split, disorder,
  fake ClientHello, …) and measures the success rate and latency of each.
- **Report** — produces a Markdown/HTML report with ready-to-use parameters for
  tools such as GoodbyeDPI, zapret, byedpi and gecit.

Those tools are the medicine; dpiprisma is the diagnosis that tells you the
right dose.

## Build

Requires Go 1.25 or newer.

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
| `--parallel` | `4` | Domains scanned at the same time |
| `--doh` | Cloudflare | Trusted DNS-over-HTTPS endpoint |
| `-v` | off | Print debug logs for every step (to stderr) |

Later features need raw packet access: Npcap on Windows or libpcap on
Linux/macOS, plus administrator/root privileges.

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
