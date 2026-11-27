# `nhilens` CLI Reference, Multi-Account Loop & Supply-Chain Verification

This reference covers full CLI usage, flags, multi-account/multi-region scanning loops, configuration, and release verification. For the quickstart and overview, see [README.md](../README.md).

---

## Command Reference

Running `nhilens` with no arguments prints help only — it **never** scans implicitly.

```bash
# Try offline with a realistic 12-identity synthetic account (zero AWS credentials needed)
nhilens demo
nhilens demo --no-write --format sarif

# Scan an AWS account (strictly read-only), persist to SQLite, and print a ranked table
nhilens scan --profile sandbox --region us-east-1 --since 90d --out ./nhilens-out

# Emit SARIF 2.1.0 for GitHub Code Scanning + CI gate (exit code 2 on high/critical)
nhilens scan --profile sandbox --region us-east-1 --format sarif --fail-on high --out ./nhilens-out > nhilens.sarif

# Suppress documented, time-bounded risk acceptances via .nhilens-ignore.yaml
nhilens scan --profile sandbox --region us-east-1 --ignore .nhilens-ignore.yaml --out ./nhilens-out

# Faster scan on large accounts (skips Access Advisor jobs; R2 is skipped without false positives)
nhilens scan --profile sandbox --region us-east-1 --skip-service-last-accessed --out ./nhilens-out

# Intersect R1/R6/R7 checks with an AWS Organizations SCP JSON file
nhilens scan --profile sandbox --region us-east-1 --scp-file ./org-scp.json --out ./nhilens-out

# Generate offline reports (html, json, sarif, markdown, csv) from a saved SQLite DB
nhilens report --in ./nhilens-out/nhilens.db --out ./nhilens-out/report.html
nhilens report --in ./nhilens-out/nhilens.db --out ./nhilens-out/report.sarif --format sarif

# Compare two scans (separate DBs, or previous vs. latest run inside the same DB)
nhilens diff --base ./nhilens-out/yesterday.db --head ./nhilens-out/today.db --format markdown --fail-on-new high
nhilens diff --base ./nhilens-out/nhilens.db

# List all built-in risk rules (R1–R8) or print guardrails + AWS CLI / Terraform remediation snippets
nhilens explain
nhilens explain R6
```

---

## Key Flags

| Command | Flag | Default | Description |
|---|---|---|---|
| `demo` | `--out` | `./nhilens-demo` | Output directory for synthetic `nhilens.db` and `report.html` |
| `demo` | `--format` | `table` | Console output format (`table`, `json`, `sarif`, `markdown`, or `csv`) |
| `demo` | `--no-write` | `false` | Print console output only without writing artifacts |
| `scan` | `--profile` | *(chain)* | AWS shared config/credentials profile |
| `scan` | `--region` | `us-east-1` / config | AWS region override (also scopes regional CloudTrail lookup) |
| `scan` | `--since` | `90d` | CloudTrail lookback window (capped at AWS's 90d Event History limit) |
| `scan` | `--max-events` | `5000` | Max CloudTrail management events to inspect (`0` disables CloudTrail lookup) |
| `scan` | `--skip-service-last-accessed` | `false` | Skip IAM Access Advisor jobs (faster on large accounts; skips R2) |
| `scan` | `--include-service-linked-roles` | `false` | Evaluate risk rules against `/aws-service-role/` roles (excluded by default) |
| `scan` | `--ignore` | *(none)* | Path to optional `.nhilens-ignore.yaml` baseline/suppression file ([example](nhilens-ignore.example.yaml)) |
| `scan` | `--scp-file` | *(none)* | Optional AWS Organizations SCP JSON file intersected with R1/R6/R7 checks |
| `scan` | `--config` | *(none)* | Path to optional `nhilens.yaml` ([example](nhilens.example.yaml)) |
| `scan` | `--out` | `./nhilens-out` | Output directory for `nhilens.db` |
| `scan` | `--format` | `table` | Console output format (`table`, `json`, `sarif`, `markdown`, or `csv`) |
| `scan` | `--fail-on` | *(none)* | Exit code `2` if any active finding meets/exceeds `low`, `medium`, `high`, or `critical` |
| `report` | `--in` | `./nhilens-out/nhilens.db` | Input SQLite database produced by `nhilens scan` or `nhilens demo` |
| `report` | `--out` | `./nhilens-out/report.<ext>` | Output report path |
| `report` | `--format` | `html` | Report output format (`html`, `json`, `sarif`, `markdown`, or `csv`) |
| `diff` | `--base` / `--head` | *(required)* | Baseline and head SQLite databases (omit `--head` to compare the last two scans in one DB) |
| `diff` | `--base-scan` / `--head-scan` | *(latest)* | Optional specific scan IDs to compare |
| `diff` | `--format` | `table` | Diff output format (`table`, `json`, or `markdown`) |
| `diff` | `--fail-on-new` | *(none)* | Exit code `2` if any newly introduced or escalated finding meets/exceeds severity |

---

## Scanning Multiple Accounts & Regions (Temporary Profile Loop)

Native AWS Organizations scanning and multi-region CloudTrail aggregation are the primary focus of **`v0.3`** (see the Roadmap in [README.md](../README.md#roadmap)). Until `v0.3` ships, you can audit multiple accounts and regions without DB collisions using a shell loop over configured AWS CLI/SSO profiles:

```bash
for profile in sandbox-ai dev-platform staging-ml; do
  for region in us-east-1 eu-west-1; do
    out="./nhilens-out/${profile}-${region}"
    nhilens scan --profile "$profile" --region "$region" --since 90d --out "$out"
    nhilens report --in "$out/nhilens.db" --out "$out/report.html"
  done
done
```

---

## Configuration & Suppressions

- **Custom heuristics, thresholds & scoring**: Copy [nhilens.example.yaml](nhilens.example.yaml) and pass `--config nhilens.yaml`.
- **Time-bounded risk acceptances**: Copy [nhilens-ignore.example.yaml](nhilens-ignore.example.yaml) and pass `--ignore .nhilens-ignore.yaml` (suppressed findings still appear in SARIF `suppressions[]` for auditability).
- **Rule definitions (`R1–R8`)**: See [rules.md](rules.md) or run `nhilens explain <RULE_ID>`.

---

## Verifying Release Supply Chain (Cosign, SHA-256, SBOM, SLSA)

Every GitHub Release publishes:
- Static binaries (`linux`, `darwin`, `windows` × `amd64`, `arm64`, compiled with `CGO_ENABLED=0`)
- CycloneDX JSON SBOMs (`*.sbom.json`)
- Keyless Cosign signatures (`checksums.txt.sigstore.json`)
- GitHub SLSA Build Provenance attestations, verified automatically by the post-release `verify-release` job

To verify a downloaded archive locally before running:

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/devel0mer/nhilens/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
sha256sum -c checksums.txt --ignore-missing
```

### Build from Source (Go 1.26+)

```bash
git clone https://github.com/devel0mer/nhilens.git
cd nhilens
CGO_ENABLED=0 go build -o nhilens ./cmd/nhilens
```

Or via `go install`:

```bash
CGO_ENABLED=0 go install github.com/devel0mer/nhilens/cmd/nhilens@latest
```
