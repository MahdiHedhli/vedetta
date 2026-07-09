# Contributing to Vedetta

Thanks for your interest in Vedetta! It's an open-source, self-hosted network
security watchtower, currently in **public beta** — expect rough edges, and please
tell us about them.

## Ways to contribute

- **Report a bug** — open a [bug report](https://github.com/MahdiHedhli/vedetta/issues/new?template=bug_report.md).
- **Request a feature** — open a [feature request](https://github.com/MahdiHedhli/vedetta/issues/new?template=feature_request.md).
- **Report a security issue** — **do not** open a public issue; follow
  [SECURITY.md](SECURITY.md).
- **Ask / discuss** — the [Discord](https://discord.gg/aubRTSWRyc) (`#dev-discussion`, `#support`).
- **Send a pull request** — see below.

## Development setup

Vedetta is a set of independent Go modules plus a React frontend and a Fluent Bit
collector:

| Component | Path | Toolchain |
|-----------|------|-----------|
| Core backend | `backend/` | Go (CGO — needs a C compiler for SQLite) |
| Native sensor | `sensor/` | Go + `libpcap-dev` (packet capture) |
| Telemetry daemon | `telemetry/` | Go |
| Threat network | `threat-network/` | Go (CGO/SQLite) |
| Frontend | `frontend/` | Node 22 + Vite |
| Collector | `collector/` | Fluent Bit + Lua/Python tests |

Run the stack locally:

```sh
cp .env.example .env          # then edit as needed
docker compose up --build     # Core + collector + frontend (beta scope)
```

Run a component's tests directly, e.g.:

```sh
cd backend && go test ./...
cd frontend && npm ci && npm run build
```

## Pull requests

1. **Branch off `main`** (`fix/…`, `feat/…`, `docs/…`, `chore/…`).
2. **Keep it focused** — one logical change per PR, with a clear description of
   the problem and the fix.
3. **Add or update tests** for behavior changes. Regression fixes should include a
   test that fails without the fix.
4. **CI must be green.** Every PR runs, per `.github/workflows/ci.yml`:
   - Go: `build`, `vet`, `test`, and `govulncheck` (source + binary mode) per module;
   - Frontend: `npm ci`, `npm audit` (production deps block on high/critical), `build`;
   - Collector: the syslog/CEF parser regression guard;
   - Secret scan: `gitleaks` over the tree, history, and the PR diff.
5. **Never commit real network data.** Use documentation-reserved values only —
   RFC 5737 IPs (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`), RFC 7042 MACs
   (`00:00:5E:00:53:xx`), and `.example` / `.local` placeholders. Real IPs, MACs,
   hostnames, captures, or credentials must never enter the repo.
6. **Review, don't self-merge.** PRs are merged after an independent review, not by
   their author.

## Commit messages

Use a short, imperative summary with a conventional prefix
(`fix(scope): …`, `feat(scope): …`, `docs: …`, `chore: …`) and a body explaining
*why*. Reference issues where relevant.

## Code of Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
