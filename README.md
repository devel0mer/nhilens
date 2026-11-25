# nhilens

**Which AI agents and non-human identities are running in your AWS account—and what can they do?**

`nhilens` is an open-source, strictly read-only Go CLI that inventories IAM roles, users, and access keys, scores AI-agent/automation likelihood from 7 configurable signals (tags, names, trusts, programmatic keys, AI/LLM service access, and CloudTrail `userAgent` traces), surfaces ownership gaps, detects privilege escalation & loose trust paths (**R1–R8**), tracks scan diffs, and exports offline HTML graphs and SARIF 2.1.0 for CI.

![nhilens CLI demo](docs/assets/demo.gif)

*(Synthetic sandbox demo — open [docs/sample-report.html](docs/sample-report.html) in a browser for the interactive offline Cytoscape.js report. Suggested GitHub topics: `aws`, `iam`, `ai-agents`, `nhi`, `security-audit`, `golang`, `sarif`, `bedrock`)*

## Design Guarantees

- **Strictly read-only**: `nhilens` never calls any mutating AWS API. Attach only the minimal 8-action policy in [docs/iam-policy.json](docs/iam-policy.json).
- **Standard AWS credential chain**: Uses environment variables, shared profiles (`--profile`), AWS SSO, or instance/task credentials. Never prompts for or stores AWS keys.
- **No telemetry**: Makes zero outbound network calls except to AWS APIs.
- **Single static binary (pure Go)**: Compiled with `CGO_ENABLED=0` using pure-Go SQLite (`modernc.org/sqlite`) and vendored/embedded Cytoscape.js (zero CDN requests when viewing reports).
- **Honest heuristics**: Agent detection outputs a configurable likelihood (`none`, `possible`, `likely`) with the exact matched signals—never a hard claim.

---

## How `nhilens` Compares to Existing AWS IAM Tools

`nhilens` is **not** a replacement for full CSPM scanners or deep attack-path solvers—it is a focused, single-binary **non-human identity (NHI) & AI-agent governance lens**:

| Tool | Primary Strength | Where `nhilens` Fits |
|---|---|---|
| **Prowler / ScoutSuite** | Broad multi-service cloud posture & CIS/compliance benchmarks | Use those for account-wide compliance; use `nhilens` specifically to inventory non-human/AI identities, surface ownership gaps, and rank AI-capable identities |
| **Cloudsplaining** | Deep per-action IAM policy analysis (data exfiltration, infra modification, privilege escalation) | Use Cloudsplaining for exhaustive policy action triage; use `nhilens` to correlate IAM policies, AI/LLM service access (`bedrock`, `sagemaker`, `q`), trust policies, Access Advisor usage, and CloudTrail IPs per identity |
| **PMapper** | Graph-based multi-hop IAM privilege escalation path solving | Use PMapper for transitive escalation graphs; use `nhilens` for fast, zero-dependency, offline HTML/JSON snapshots oriented around AI-agent & automation ownership and blast radius |

## Installation

### Via `go install` (Go 1.26+)
```bash
CGO_ENABLED=0 go install github.com/devel0mer/nhilens/cmd/nhilens@latest
```

### Pre-built Binaries (GitHub Releases + Cosign Verification)
Download the archive for your OS/architecture (`linux`, `darwin`, `windows` × `amd64`, `arm64`) from the GitHub Releases page, verify the keyless Cosign signature and SHA-256 checksums, and place `nhilens` on your `PATH`:

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/devel0mer/nhilens/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
sha256sum -c checksums.txt --ignore-missing
```

### Docker (Distroless, Non-Root)
```bash
docker build -t nhilens:local .
docker run --rm -v ~/.aws:/home/nonroot/.aws:ro nhilens:local version
```

### Build from Source
```bash
git clone https://github.com/devel0mer/nhilens.git
cd nhilens
CGO_ENABLED=0 go build -o nhilens ./cmd/nhilens
```

---

## Minimal IAM Permissions

Attach [docs/iam-policy.json](docs/iam-policy.json) to the IAM role or user you use to run `nhilens`. It grants **only** these 8 read-only actions:

- `sts:GetCallerIdentity`
- `iam:GetAccountAuthorizationDetails`
- `iam:GetLoginProfile`
- `iam:ListAccessKeys`
- `iam:GetAccessKeyLastUsed`
- `iam:GenerateServiceLastAccessedDetails`
- `iam:GetServiceLastAccessedDetails`
- `cloudtrail:LookupEvents`

---

## Usage

Running `nhilens` with no arguments prints help only—it **never** scans implicitly.

```bash
# Print help
nhilens

# Print version
nhilens version

# Scan a sandbox AWS account, persist to SQLite, and print a ranked table
nhilens scan --profile sandbox --region us-east-1 --since 90d --out ./nhilens-out

# Machine-readable JSON or SARIF (for GitHub Code Scanning) + CI failure gate (exit code 2)
nhilens scan --profile sandbox --region us-east-1 --format sarif --fail-on high --out ./nhilens-out > nhilens.sarif

# Suppress documented, time-bounded risk acceptances via .nhilens-ignore.yaml
nhilens scan --profile sandbox --region us-east-1 --ignore .nhilens-ignore.yaml --out ./nhilens-out

# Faster scan on large accounts (skips Access Advisor jobs; R2 is skipped without false positives)
nhilens scan --profile sandbox --region us-east-1 --skip-service-last-accessed --out ./nhilens-out

# Generate a standalone offline HTML report (or json, sarif, markdown, csv) from a scan database
nhilens report --in ./nhilens-out/nhilens.db --out ./nhilens-out/report.html
nhilens report --in ./nhilens-out/nhilens.db --out ./nhilens-out/report.sarif --format sarif

# Compare two scans (separate DBs, or previous vs. latest run inside the same DB)
nhilens diff --base ./nhilens-out/yesterday.db --head ./nhilens-out/today.db --format markdown --fail-on-new high
nhilens diff --base ./nhilens-out/nhilens.db

# List all risk rules (R1–R8) or display guardrails + AWS CLI / Terraform remediation snippets
nhilens explain
nhilens explain R5
```

### Scanning Multiple Accounts & Regions (Profile Loop)

Native AWS Organizations orchestration is intentionally out of scope for v0.x, but you can audit multiple accounts and regions cleanly without DB collisions using a shell loop over configured AWS CLI/SSO profiles:

```bash
for profile in sandbox-ai dev-platform staging-ml; do
  for region in us-east-1 eu-west-1; do
    out="./nhilens-out/${profile}-${region}"
    nhilens scan --profile "$profile" --region "$region" --since 90d --out "$out"
    nhilens report --in "$out/nhilens.db" --out "$out/report.html"
  done
done
```

### Key Flags

| Command | Flag | Default | Description |
|---|---|---|---|
| `scan` | `--profile` | *(chain)* | AWS shared config/credentials profile |
| `scan` | `--region` | `us-east-1` / config | AWS region override |
| `scan` | `--since` | `90d` | CloudTrail lookback window (capped at AWS's 90d Event History limit) |
| `scan` | `--max-events` | `5000` | Max CloudTrail management events to inspect (`0` disables CloudTrail lookup) |
| `scan` | `--skip-service-last-accessed` | `false` | Skip IAM Access Advisor jobs (faster on large accounts; skips R2) |
| `scan` | `--include-service-linked-roles` | `false` | Evaluate risk rules against `/aws-service-role/` roles (excluded by default) |
| `scan` | `--ignore` | *(none)* | Path to optional `.nhilens-ignore.yaml` baseline/suppression file (see [docs/nhilens-ignore.example.yaml](docs/nhilens-ignore.example.yaml)) |
| `scan` | `--scp-file` | *(none)* | Optional AWS Organizations SCP JSON file intersected with R1 admin-wildcard checks |
| `scan` | `--config` | *(none)* | Path to optional `nhilens.yaml` |
| `scan` | `--out` | `./nhilens-out` | Output directory for `nhilens.db` |
| `scan` | `--format` | `table` | Console output format (`table`, `json`, `sarif`, `markdown`, or `csv`) |
| `scan` | `--fail-on` | *(none)* | Exit code `2` if any active finding meets/exceeds `low`, `medium`, `high`, or `critical` |
| `report` | `--in` | `./nhilens-out/nhilens.db` | Input SQLite database produced by `nhilens scan` |
| `report` | `--out` | `./nhilens-out/report.<ext>` | Output report path |
| `report` | `--format` | `html` | Report output format (`html`, `json`, `sarif`, `markdown`, or `csv`) |
| `diff` | `--base` / `--head` | *(required)* | Baseline and head SQLite databases (omit `--head` to compare the last two scans in one DB) |
| `diff` | `--base-scan` / `--head-scan` | *(latest)* | Optional specific scan IDs to compare |
| `diff` | `--format` | `table` | Diff output format (`table`, `json`, or `markdown`) |
| `diff` | `--fail-on-new` | *(none)* | Exit code `2` if any newly introduced or escalated finding meets/exceeds severity |

---

## Configuration (`nhilens.yaml`)

All heuristics, rule toggles, stale thresholds, and scoring weights are configurable via an optional `nhilens.yaml` file. Copy [docs/nhilens.example.yaml](docs/nhilens.example.yaml) as a starting point and pass `--config nhilens.yaml`.

---

## Rules, Scoring & Sample Report

- Full rule definitions (**R1–R8**: wildcard permissions, unused permissions, no owner, stale/shared key, loose trust, privilege escalation path, sensitive service wildcard, key hygiene), heuristic agent signals, and scoring weights are documented in [docs/rules.md](docs/rules.md) — or inspect any rule from the terminal with `nhilens explain <RULE_ID>`.
- Preview a **synthetic** offline HTML report (fake account `111122223333`) with the embedded Cytoscape.js graph by opening [docs/sample-report.html](docs/sample-report.html) in any browser.

---

## Sensitive Data Warning

> **Review before sharing:** The SQLite database (`nhilens.db`, created with owner-only `0600` permissions) and generated HTML/JSON/SARIF reports contain AWS account IDs, IAM ARNs, role/user names, tag values, policy documents, and best-effort CloudTrail source IP addresses. Treat scan outputs as sensitive security artifacts, keep them out of version control, and review or redact them before sharing externally.

## Limitations & Non-Goals

- **Heuristic AI agent vs. automation classification**: Signals are configurable heuristics, not definitive attribution. Generic automation signals alone (e.g., programmatic access keys, CI OIDC trusts, `ci`/`deploy` names) are classified as `workload_kind=automation` and capped at `45%` (`possible`) so ordinary CI/CD users do not false-positive as `likely` AI agents without at least one AI-specific signal.
- **CloudTrail is single-region**: `cloudtrail:LookupEvents` operates per AWS region (`--region`). Key usage, `userAgent` traces, and multi-IP activity in other regions are not included in a single regional scan; run `nhilens scan` per active region where needed.
- **CloudTrail & Access Advisor windows**: CloudTrail Event History covers management events up to 90 days (subject to `--max-events` caps; multi-IP key detection is best-effort). Access Advisor covers the trailing 400 days and may lag slightly.
- **Identity-policy upper bound**: Permission analysis inspects attached managed, inline, and group policies. Permissions boundaries and optional `--scp-file` JSON guardrails are intersected for R1 admin-wildcard capping, but full action-level SCP/boundary intersections, resource-based policies, and session policies are not evaluated.
- **Service-linked roles**: AWS-managed `/aws-service-role/` roles are inventoried and labeled but excluded from risk findings by default.
- **Out of scope for v0.x**: Credential brokering/issuing, auto-remediation, Azure/GCP, SPIFFE/SPIRE, web servers, and built-in multi-account AWS Organizations orchestration (see the profile-loop recipe above for multi-account runs).

---

## Testing & Sandbox Fixture

```bash
# Run all unit tests (mocked AWS clients only — zero real AWS calls)
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=0 go test -count=1 ./...
```

To validate end-to-end against an isolated **sandbox** AWS account (never production), see the manual Terraform fixture in [test/sandbox-fixture/README.md](test/sandbox-fixture/README.md). It is never run automatically in CI.

## License

Apache-2.0. See [LICENSE](LICENSE). Vendored Cytoscape.js is licensed under MIT ([internal/report/assets/cytoscape.LICENSE.txt](internal/report/assets/cytoscape.LICENSE.txt)).
