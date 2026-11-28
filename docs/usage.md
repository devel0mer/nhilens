# `nhilens` CLI Reference, AWS Organizations Setup & Supply-Chain Verification

This reference covers full CLI usage, flags, AWS Organizations / multi-account setup, multi-region CloudTrail scanning, configuration, and release verification. For the quickstart and overview, see [README.md](../README.md).

---

## Command Reference

Running `nhilens` with no arguments prints help only — it **never** scans implicitly.

```bash
# Try offline with realistic synthetic data (zero AWS credentials needed)
nhilens demo
nhilens demo --org
nhilens demo --org --no-write --format sarif

# Scan a single AWS account (strictly read-only), persist to SQLite, and print a ranked table
nhilens scan --profile sandbox --region us-east-1 --since 90d --out ./nhilens-out

# Multi-region CloudTrail aggregation (catches cross-region R4 shared keys & AI userAgent traces)
nhilens scan --profile sandbox --regions us-east-1,us-west-2,eu-west-1 --since 90d --out ./nhilens-out
nhilens scan --profile sandbox --regions all --since 30d --out ./nhilens-out

# Scan an entire AWS Organization (discovers ACTIVE accounts & effective Root/OU/Account SCPs)
nhilens scan --org --assume-role-name nhilens-readonly --regions us-east-1,eu-west-1 --out ./org-out

# Scan an Organization while excluding specific accounts (or targeting a subset via --accounts)
nhilens scan --org --assume-role-name nhilens-readonly --exclude-accounts 999988887777 --out ./org-out

# Scan an explicit list of AWS accounts without Organizations permissions
nhilens scan --accounts 111111111111,222222222222 --assume-role-name nhilens-readonly --external-id my-audit-id --out ./multi-out

# Emit SARIF 2.1.0 for GitHub Code Scanning + CI gate (exit code 2 on high/critical)
nhilens scan --profile sandbox --region us-east-1 --format sarif --fail-on high --out ./nhilens-out > nhilens.sarif

# Suppress documented, time-bounded risk acceptances via .nhilens-ignore.yaml
nhilens scan --profile sandbox --region us-east-1 --ignore .nhilens-ignore.yaml --out ./nhilens-out

# Faster scan on large accounts (skips Access Advisor jobs; R2 is skipped without false positives)
nhilens scan --profile sandbox --region us-east-1 --skip-service-last-accessed --out ./nhilens-out

# Intersect R1/R6/R7 checks with a local AWS Organizations SCP JSON file (for single-account runs)
nhilens scan --profile sandbox --region us-east-1 --scp-file ./org-scp.json --out ./nhilens-out

# Generate offline reports (html, json, sarif, markdown, csv) from a saved SQLite DB
nhilens report --in ./org-out/nhilens.db --out ./org-out/report.html
nhilens report --in ./org-out/nhilens.db --out ./org-out/report.sarif --format sarif

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
| `demo` | `--org` | `false` | Run a 3-account, 2-region synthetic AWS Organizations rollup demo |
| `demo` | `--out` | `./nhilens-demo` | Output directory for synthetic `nhilens.db` and `report.html` |
| `demo` | `--format` | `table` | Console output format (`table`, `json`, `sarif`, `markdown`, or `csv`) |
| `demo` | `--no-write` | `false` | Print console output only without writing artifacts |
| `scan` | `--profile` | *(chain)* | AWS shared config/credentials profile |
| `scan` | `--region` | `us-east-1` / config | Primary AWS region override |
| `scan` | `--regions` | *(single `--region`)* | Comma-separated AWS regions for parallel CloudTrail aggregation, or `all` for the 17 default-enabled AWS regions |
| `scan` | `--org` | `false` | Discover and scan all `ACTIVE` accounts in the AWS Organization (auto-loads effective SCPs) |
| `scan` | `--accounts` | *(none)* | Comma-separated 12-digit AWS account IDs to scan (filters `--org` when combined) |
| `scan` | `--exclude-accounts` | *(none)* | Comma-separated 12-digit AWS account IDs to skip in `--org` / `--accounts` mode |
| `scan` | `--assume-role-name` | *(none)* | Read-only IAM role name to assume in target member accounts (e.g. `nhilens-readonly`) |
| `scan` | `--external-id` | *(none)* | Optional STS `ExternalId` passed when assuming `--assume-role-name` |
| `scan` | `--account-concurrency` | `4` | Maximum AWS accounts scanned concurrently in multi-account mode (`1..16`) |
| `scan` | `--skip-org-scps` | `false` | Skip automatic Organizations SCP resolution in `--org` mode |
| `scan` | `--since` | `90d` | CloudTrail lookback window (capped at AWS's 90d Event History limit) |
| `scan` | `--max-events` | `5000` | Max CloudTrail management events per region (`0` disables CloudTrail lookup) |
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

## AWS Organizations & Multi-Account Setup

### 1. Central Auditor Role (Management or Delegated Admin Account)
Attach [docs/iam-policy-org.json](iam-policy-org.json) to the identity running `nhilens scan --org`. It grants strictly read-only Organizations discovery/SCP reading (`DescribeOrganization`, `ListAccounts`, `ListParents`, `ListPoliciesForTarget`, `DescribePolicy`), `sts:AssumeRole` scoped exclusively to `arn:aws:iam::*:role/nhilens-readonly`, and the 8 read-only single-account audit actions.

### 2. Read-Only Audit Role in Each Member Account (`nhilens-readonly`)
Deploy a role named `nhilens-readonly` (e.g. via AWS CloudFormation StackSets or Terraform) in each member account with:
- **Permissions policy:** [docs/iam-policy.json](iam-policy.json) (8 strictly read-only actions)
- **Trust policy** (replace `<SECURITY_ACCOUNT_ID>` and optional `<EXTERNAL_ID>`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<SECURITY_ACCOUNT_ID>:role/nhilens-org-auditor"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "<OPTIONAL_EXTERNAL_ID>"
        }
      }
    }
  ]
}
```

### 3. Run the Org Audit

```bash
nhilens scan \
  --org \
  --assume-role-name nhilens-readonly \
  --external-id "<OPTIONAL_EXTERNAL_ID>" \
  --regions us-east-1,eu-west-1 \
  --out ./org-out

nhilens report --in ./org-out/nhilens.db --out ./org-out/report.html
```

- **Resilience:** If an account is unreachable or missing `nhilens-readonly`, `nhilens` records the error in `Account Breakdown` and `Coverage.AccountsFailed`, marks overall coverage `partial`, and continues scanning all remaining accounts.
- **Automatic SCPs:** In `--org` mode, `nhilens` walks each member account's Root → OU → Account hierarchy, merges policies per level and intersects across levels (matching AWS Organizations evaluation semantics and respecting the Management Account SCP exemption), and caches results across sibling accounts.
- **Alternative (Profile Loop):** If you use AWS SSO profiles without cross-account `AssumeRole`, you can still loop over profiles:

```bash
for profile in sandbox-ai dev-platform staging-ml; do
  out="./nhilens-out/${profile}"
  nhilens scan --profile "$profile" --regions us-east-1,eu-west-1 --since 90d --out "$out"
  nhilens report --in "$out/nhilens.db" --out "$out/report.html"
done
```

---

## Configuration & Suppressions

- **Custom heuristics, regions, thresholds & scoring**: Copy [nhilens.example.yaml](nhilens.example.yaml) and pass `--config nhilens.yaml`.
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
