# dpiprisma

[![CI](https://github.com/mehmetalitilgen/dpiprisma/actions/workflows/ci.yml/badge.svg)](https://github.com/mehmetalitilgen/dpiprisma/actions/workflows/ci.yml)

Give it a domain and dpiprisma tells you **how** it is blocked on your network,
**where** the DPI device sits, and **which** circumvention parameters actually
work — in a readable report.

> **Status: early development.** The features below describe the goal of the
> project; most of them are not implemented yet.

## What it does

- **Diagnose** — tells DNS poisoning, IP-level blackholing and SNI-based
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
./dpiprisma
```

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
