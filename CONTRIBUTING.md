# Contributing

Thanks for taking the time. Bug reports, questions and pull requests are all
welcome through [GitHub issues](https://github.com/mehmetalitilgen/dpiprisma/issues)
and pull requests.

## Build and test

dpiprisma needs Go 1.25 or newer and nothing else; it is pure Go with no C
toolchain or packet-capture driver.

```sh
go build ./cmd/dpiprisma
go test ./...
```

CI runs these checks on every push, so run them before opening a pull
request:

```sh
gofmt -l .                                             # must print nothing
go vet ./...
go test -race ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
```

Tests that need the internet are opt-in: set `DPIPRISMA_INTEGRATION=1` to
run them. Tests that need raw sockets skip themselves unless they run as root
on Linux. The report tests compare against golden files; after an intended
output change, regenerate them with `go test ./internal/report -update`.

## Where things live

| Directory | What it holds |
|---|---|
| `cmd/dpiprisma` | the `main` package; only sets the version and calls the CLI |
| `internal/cli` | cobra commands: `scan`, `locate`, `matrix`, `report` |
| `internal/probe` | DNS, DoH, TCP and TLS probes; forged-reset forensics |
| `internal/tlsx` | ClientHello builder and SNI parser |
| `internal/packet` | IPv4/TCP parsing, checksums, raw-socket capture |
| `internal/locate` | TTL walks that find the DPI device and the server |
| `internal/strategy` | bypass strategies and their registry |
| `internal/runner` | runs strategies and scores them |
| `internal/report` | Markdown and HTML report, tool command recommendations |
| `internal/model` | verdicts and result types shared by the commands and the report |

## Pull requests

- Keep a pull request to one change. Small, focused changes are reviewed
  faster.
- Add or update tests next to the code you change. Regenerate golden files
  only when the output change is intended, and say so in the pull request.
- Code, comments, commit messages and documentation are in English.
- Write commit messages as a short imperative sentence that says what the
  change does, for example `Add the disorder strategy`.
- Adding a strategy: implement the `Strategy` interface in
  `internal/strategy`, register it in `registry.go`, add a test, and teach
  `internal/report/recommend.go` how to turn it into a tool command.

## Responsible use

dpiprisma is a measurement and research tool. Test only against networks and
servers you own or are authorized to test, and keep traffic minimal; see the
Disclaimer in the README. Changes that make the tool send more traffic than a
test needs, or that target third parties, will not be merged.
