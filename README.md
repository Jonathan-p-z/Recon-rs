# recon-rs

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.78%2B-orange.svg)](https://www.rust-lang.org)
[![CI](https://github.com/jonathan-p-z/Recon-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/jonathan-p-z/Recon-rs/actions/workflows/ci.yml)

**recon-rs** is a passive, rate-limited attack-surface reconnaissance CLI for bug bounty hunters and security researchers. It enumerates subdomains, probes them over HTTP(S), flags likely subdomain takeovers, tracks what changed between scans, and writes clean local Markdown reports, all against strictly authorized, in-scope targets.

## 📋 Table of contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Deployment](#-deployment)
- [Legal disclaimer & responsible disclosure](#-legal-disclaimer--responsible-disclosure)
- [Roadmap](#-roadmap)
- [License](#-license)
- [Author](#-author)

## ✨ Features

- **🔤 Pattern-driven subdomain enumeration**: extracts a target's naming convention (environment, region, technical function, version, separator tokens) from a seed list of already-known subdomains, then generates scored candidates worth testing instead of blindly brute-forcing a generic wordlist.
- **🌐 Async DNS resolution with mandatory rate limiting**: concurrent resolution over configurable DNS servers via [`hickory-resolver`](https://github.com/hickory-dns/hickory-dns), governed by a global requests/second and max-concurrency cap that cannot be bypassed from the CLI.
- **🔎 Async HTTP/HTTPS probing**: a single, honest `GET` per resolved host (status code, title, headers), rate-limited **per host** so programs with a "N req/s per host" rule are respected exactly, not over- or under-utilized.
- **🕳️ Subdomain takeover & passive signature detection**: CNAME-pattern rules (dangling S3 buckets, Heroku apps) and response-pattern rules (exposed Jenkins/Kibana, outdated Apache, and more), each scored `critical` / `high` / `medium` / `low`.
- **📊 Scan-to-scan diffing in PostgreSQL**: every result is persisted per target domain; each new scan is automatically diffed against the last completed one, surfacing newly appeared subdomains, disappeared ones, and HTTP status changes.
- **📄 Local Markdown report generation**: one timestamped report per scan plus a rolling `_latest.md`, written to disk only, with no webhook, no email, no third-party exfiltration of any kind.
- **🧭 CLI-orchestrated pipeline**: a single `recon-cli` binary chains candidate generation → resolution → probing → persistence → diffing → reporting, with scope validation enforced *before* any network request is made.
- **⏱️ Recurring, multi-target scheduling**: ships with systemd `--user` template units (`recon-rs@<target>.service` / `.timer`) to run independent, staggered scans for several targets unattended, with no root privileges required.

## 🏗️ Architecture

`recon-rs` is a Cargo workspace split into three crates, each with a single clear responsibility:

```
recon-rs/
├── crates/
│   ├── recon-core/        # Engine: permutations, DNS, HTTP, scope (no I/O side effects beyond network calls)
│   │   └── src/
│   │       ├── permutation_engine.rs   # naming pattern extraction, candidate generation, signature scoring
│   │       ├── resolver.rs             # async DNS resolution (hickory-resolver) + rate limiting
│   │       ├── prober.rs               # async HTTP/HTTPS probing (reqwest) + per-host rate limiting
│   │       ├── program.rs              # bug bounty program scope validation (matches_scope)
│   │       └── rate_limit.rs           # shared rate-limiting primitives (governor)
│   │
│   ├── recon-db/          # Persistence: PostgreSQL storage, migrations, scan diffing
│   │   ├── migrations/                 # sqlx migrations (scans, scan_results)
│   │   └── src/
│   │       ├── repository.rs           # ScanRepository: create/finish scans, save/fetch results
│   │       ├── diff.rs                 # pure scan-to-scan comparison (no I/O)
│   │       ├── record.rs               # ScanResultRecord model
│   │       └── config.rs               # DbConfig (DATABASE_URL loading/connection)
│   │
│   └── recon-cli/         # Binary: CLI, pipeline orchestration, config loading, report rendering
│       └── src/
│           ├── main.rs                 # argument parsing, scope check, pipeline entry point
│           ├── pipeline.rs             # run_scan: full orchestration of one scan
│           ├── configs.rs              # loads patterns.toml / resolver.toml / prober.toml
│           ├── report.rs               # Markdown report rendering + writing
│           └── seed.rs                 # --seed-file parsing
│
├── config/                 # Default TOML configuration + per-program overrides
├── deploy/                 # systemd template units + install.sh
└── reports/                # Generated Markdown reports (git-ignored)
```

Data flows strictly one way through the pipeline, and nothing leaves the machine except outbound DNS/HTTP requests to the in-scope target itself:

```
 seed file ──► permutation_engine ──► candidate FQDNs
                                           │
                                           ▼
                                DnsResolver  (rate-limited, async)
                                           │
                                           ▼
                                HttpProber   (rate-limited per host, async)
                                           │
                                           ▼
                        recon-db  (persist results + diff vs previous scan)
                                           │
                                           ▼
                        Markdown report  (local file only)
```

## 📦 Installation

### Prerequisites

| Requirement | Notes |
|---|---|
| Rust toolchain | Stable, edition 2021 (1.78+), install via [rustup](https://rustup.rs) |
| PostgreSQL | Any recent version (13+) reachable via a connection string |
| `cargo` | Ships with the Rust toolchain |

### Build from source

```bash
git clone https://github.com/jonathan-p-z/Recon-rs.git
cd Recon-rs

# Build everything (recon-core, recon-db, recon-cli)
cargo build --release

# Run the test suite (DB- and network-dependent tests are #[ignore]d by default)
cargo test --workspace
```

The release binary is produced at `target/release/recon-cli`.

### Database setup

Create a database and point `DATABASE_URL` at it; `recon-db`'s migrations create the schema automatically on first connection:

```bash
createdb recon_rs
cp .env.example .env
# edit .env with your real connection string
```

## ⚙️ Configuration

`recon-cli` reads three TOML files from `--config` (default: `config/`), plus an optional program file via `--program`.

| File | Purpose |
|---|---|
| `config/patterns.toml` | Naming-dictionary tokens (environments, regions, technical functions, versions, separators) used for candidate generation, plus the `[[vuln_signatures.rule]]` table driving takeover/exposure detection. |
| `config/resolver.toml` | DNS resolver behavior: `requests_per_second`, `max_concurrent`, `timeout_ms`, `dns_servers`. |
| `config/prober.toml` | HTTP prober behavior: `requests_per_second` (per host), `max_concurrent`, `timeout_ms`, `user_agent`, `follow_redirects`. |
| `config/programs/<program>.toml` | Optional, per bug bounty program: an authorized `[scope]` plus a `[prober]` override (rate limit, custom headers, hacker handle). Loaded via `--program`; `--target` is validated against `[scope]` before anything else runs. |
| `.env` (from `.env.example`) | `DATABASE_URL` for `recon-db`; never commit a real value. |

Example `resolver.toml`:

```toml
requests_per_second = 10
max_concurrent = 50
timeout_ms = 3000
dns_servers = ["1.1.1.1", "8.8.8.8"]
```

Example `prober.toml`:

```toml
requests_per_second = 10
max_concurrent = 30
timeout_ms = 5000
user_agent = "recon-rs/0.1 (security research)"
follow_redirects = true
```

Example program scope file (`config/programs/acme-corp.toml`), illustrating how a program's own rules, not the CLI, set the rate limit:

```toml
[scope]
domains = ["*.acme-corp.com"]

[prober]
requests_per_second = 5        # this program's published rule: 5 req/s per host
max_concurrent = 20
timeout_ms = 5000
user_agent = "Mozilla/5.0 (compatible; recon-rs; security research)"
hacker_username = "your-handle"

[prober.custom_headers]
"X-Bug-Bounty" = "HackerOne-your-handle"
```

> A `[scope]` wildcard such as `"*.acme-corp.com"` authorizes both the base domain itself and any of its subdomains, never a substring match, so `acme-corp.com.evil.com` is correctly rejected.

Example `.env`:

```env
DATABASE_URL=postgres://user:password@localhost:5432/recon_rs
```

## 🚀 Usage

```bash
# Generic scan, no program-specific scope enforcement
cargo run --release -p recon-cli -- \
  --target example.com \
  --seed-file seed_example.txt

# Scan enforced against an authorized program scope
cargo run --release -p recon-cli -- \
  --target example.com \
  --program config/programs/acme-corp.toml \
  --seed-file seed_example.txt \
  --config config/ \
  --output ./reports/
```

| Option | Description | Default |
|---|---|---|
| `--target <domain>` | Target domain to scan. Required. | *(none)* |
| `--config <dir>` | Directory containing `patterns.toml`, `resolver.toml`, `prober.toml`. | `config/` |
| `--output <dir>` | Directory to write Markdown reports into. | `./reports/` |
| `--program <file>` | Program config bundling `[scope]` + `[prober]` override. `--target` is refused outright if not covered by `[scope]`. | none |
| `--seed-file <file>` | File of already-known subdomains (one FQDN per line) seeding pattern extraction. | none |

There is deliberately **no** flag to override rate limiting from the command line: `requests_per_second`, `max_concurrent`, and `timeout_ms` only ever come from `resolver.toml` / `prober.toml` (or a program's `[prober]` override), so a scan's rate limit can never be silently bumped under time pressure.

### Sample report output

Each run writes `reports/<target>_<timestamp>.md` and refreshes `reports/<target>_latest.md`:

```markdown
# Rapport de recon — example.com

- Date du scan : 2026-10-18 09:12:04 UTC
- Durée du scan : 183s
- Candidats testés : 1240
- Sous-domaines résolus : 54

## 🆕 Nouveaux sous-domaines

| Sous-domaine | Statut HTTP | Priorité |
|---|---|---|
| staging-api.example.com | 200 | low |
| old-jenkins.example.com | 200 | high |
| assets-cdn.example.com | 404 | low |

## 📉 Sous-domaines disparus

_Informationnel — ces hôtes répondaient lors du scan précédent mais plus maintenant ; peut simplement indiquer une infra désactivée, pas nécessairement un problème._

- legacy-vpn.example.com

## Résumé complet

| Sous-domaine | Statut HTTP | Priorité |
|---|---|---|
| ... | ... | ... |
```

## 🛠️ Deployment

For unattended, recurring scans across several targets, `recon-rs` ships systemd `--user` **template** units: no root, no cron, no system-wide service.

- `deploy/recon-rs@.service`: one scan run for one target (`%i` is the instance name).
- `deploy/recon-rs@.timer`: the schedule for that instance, via a per-target drop-in.

```bash
./deploy/install.sh
```

This builds `recon-cli` in release mode, installs it to `~/.local/bin/`, copies `config/` to `~/.config/recon-rs/config/`, installs the template units to `~/.config/systemd/user/`, and enables + starts `recon-rs@<name>.timer` for every target defined under `~/.config/recon-rs/targets/`.

```bash
# After editing a target's targets/<name>.env (TARGET, PROGRAM_CONFIG, SEED_FILE, DATABASE_URL):
systemctl --user list-timers 'recon-rs@*'       # verify the schedule
systemctl --user start recon-rs@<name>.service  # trigger one run immediately
journalctl --user -t recon-rs-<name> -f         # follow one target's logs
```

Each instance fails safe: no `OnCalendar=` by default (nothing runs until a schedule drop-in exists), no automatic retries on failure (a persistent error must never become a request flood), and independent schedules per target so nothing overlaps by accident. See [`deploy/README.md`](deploy/README.md) for the full install/verify/add-a-target/uninstall walkthrough.

## ⚠️ Legal disclaimer & responsible disclosure

**recon-rs is built exclusively for use within the authorized scope of a legitimate bug bounty, VDP, or pentest engagement** (HackerOne, Bugcrowd, Intigriti, a private program, or an equivalent safe-harbor agreement).

- Running this tool against a domain you are **not explicitly authorized** to test is almost certainly unauthorized access and may be illegal in your jurisdiction.
- **You, the operator, are solely responsible** for confirming the target's current scope and rules of engagement *before every scan*, and for keeping any local `[scope]` / program configuration up to date. A `--program` file only enforces what it was told the last time it was edited; it has no way to know the program's real, live rules have changed.
- This tool performs **passive reconnaissance only**: DNS resolution and a single honest `GET` request per host. It never authenticates, never sends a payload, never attempts exploitation, and never disguises its `User-Agent` to evade detection or a `robots.txt`.
- No scan result, report, or telemetry is ever sent anywhere automatically; reports are written to local disk only.
- The authors and contributors accept **no liability** for misuse of this software outside an authorized engagement's scope and rules.

If in doubt about whether a target is in scope: **do not scan it**, and confirm with the program owner first.

## 🗺️ Roadmap

- [ ] Additional takeover signatures (GitHub Pages, Fastly, Azure, Shopify, Zendesk)
- [ ] JSON / SARIF report export, alongside Markdown
- [ ] Historical trend view across more than two successive scans
- [ ] Optional TLS certificate transparency (crt.sh) as a passive candidate source
- [ ] Configurable per-program notification hooks (opt-in, local-first)
- [ ] `recon-cli diff <target>` subcommand to re-render a diff without a new scan

Contributions and suggestions are welcome via issues and pull requests.

## 📄 License

Distributed under the [MIT License](LICENSE).

## 👤 Author

**Yaiito** ([@jonathan-p-z](https://github.com/jonathan-p-z))
