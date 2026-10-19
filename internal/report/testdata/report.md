# dpiprisma report

Generated 2026-10-19 12:30 UTC by dpiprisma v1.0.0.

## Diagnosis

| Domain | Verdict | Reason |
|---|---|---|
| blocked.example | sni_blocking | the server answers other names but not this one |
| poisoned.example | dns_poisoning | system DNS returned a bogus address |
| example.com | accessible | TLS handshake succeeded |

## DPI location

| Domain | Reset | DPI | Server | Fake TTL |
|---|---|---|---|---|
| blocked.example | yes | 3 hops (3 of 3 runs) | 6-7 hops | 3-5 |
| located.example | yes | 4 hops (2 of 3 runs) | 9 hops | 4-8 |

## Strategy matrix

Share of connections that got a ServerHello; median latency in parentheses.

| Domain | baseline | fakech ttl=4 | fakerst ttl=4 | split at=2 | split at=10 |
|---|---|---|---|---|---|
| blocked.example | 0% | 100% (44.5 ms) | 20% (47.0 ms) | 90% (48.0 ms) | 60% (51.0 ms) |
| example.com | 100% (30.0 ms) | - | - | - | - |

## Recommended commands

### blocked.example

Best: fakech ttl=4.

| Tool | Command | Based on |
|---|---|---|
| gecit | `sudo gecit run --fake-ttl 4` | fakech ttl=4: 10/10, median 44.5 ms |
| zapret | `nfqws --qnum=200 --dpi-desync=fake --dpi-desync-ttl=4` | fakech ttl=4: 10/10, median 44.5 ms |
| GoodbyeDPI | `goodbyedpi.exe --set-ttl 4` | fakech ttl=4: 10/10, median 44.5 ms |
| byedpi | `ciadpi --fake -1 --ttl 4` | fakech ttl=4: 10/10, median 44.5 ms |

### poisoned.example

DNS poisoning: use an encrypted resolver (DoH or DoT); gecit has one built in.

### example.com

Not blocked: a plain ClientHello succeeded 10 of 10 times.

### located.example

Not tested by the matrix; run "dpiprisma matrix" to confirm.

| Tool | Command | Based on |
|---|---|---|
| gecit | `sudo gecit run --fake-ttl 4` | fake-ttl 4-8 from locate; not tested |
| zapret | `nfqws --qnum=200 --dpi-desync=fake --dpi-desync-ttl=4` | fake-ttl 4-8 from locate; not tested |
| GoodbyeDPI | `goodbyedpi.exe --set-ttl 4` | fake-ttl 4-8 from locate; not tested |
| byedpi | `ciadpi --fake -1 --ttl 4` | fake-ttl 4-8 from locate; not tested |
