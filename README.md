# nhilens

**Which AI agents and non-human identities are running in your AWS account — and what can they do?**

List every AI agent, bot, IAM role, and static access key in an AWS account, flag the unowned and over-privileged ones, and see exactly why they're risky — strictly read-only, single static Go binary, zero telemetry.

![nhilens example audit report showing unowned AI agents, matched heuristic signals, and risk findings](docs/assets/finding-example.png)

*(Synthetic 12-identity output from `nhilens demo` — open [docs/sample-report.html](docs/sample-report.html) in any browser for the full offline interactive report.)*

---

## Try in 60 Seconds (No AWS Credentials Needed)

Run the full classification, risk scoring, and offline HTML report pipeline on a realistic synthetic AWS account (`111122223333`) with **zero AWS API calls**:

```bash
# macOS / Linux (Homebrew)
brew install devel0mer/tap/nhilens
nhilens demo
```

No Homebrew? Download a pre-built static binary (`linux`, `darwin`, `windows` × `amd64`, `arm64`) from [GitHub Releases](https://github.com/devel0mer/nhilens/releases/latest) — zero runtime dependencies, no Go toolchain required:

```bash
# Example: macOS Apple Silicon (replace archive name for Linux/Intel/Windows)
curl -fsSL https://github.com/devel0mer/nhilens/releases/latest/download/nhilens_0.2.1_darwin_arm64.tar.gz | tar -xz nhilens
./nhilens demo
```

`nhilens demo` prints a ranked risk table and writes a self-contained offline report to `./nhilens-demo/report.html` (plus `./nhilens-demo/nhilens.db`).

---

## Scan Your Own AWS Account (Strictly Read-Only)

Attach only the minimal 8-action read-only policy in [docs/iam-policy.json](docs/iam-policy.json) (`sts:GetCallerIdentity`, IAM read/Access Advisor, `cloudtrail:LookupEvents`). `nhilens` never calls any mutating AWS API and makes zero telemetry calls.

```bash
# 1. Scan an account, persist to SQLite, and print a ranked table
nhilens scan --profile sandbox --region us-east-1 --since 90d --out ./nhilens-out

# 2. Generate a standalone offline HTML report with interactive trust & policy graph
nhilens report --in ./nhilens-out/nhilens.db --out ./nhilens-out/report.html

# 3. Inspect any risk rule with AWS CLI / Terraform remediation snippets
nhilens explain R6
```

![nhilens CLI demo](docs/assets/demo.gif)

---

## Install

- **Pre-built binaries (recommended — no Go required):** Download from [GitHub Releases](https://github.com/devel0mer/nhilens/releases/latest) (`linux`, `darwin`, `windows` × `amd64`, `arm64`; shipped with SHA-256 checksums, CycloneDX SBOMs, keyless Cosign signatures, and SLSA provenance — [verification instructions](docs/usage.md#verifying-release-supply-chain-cosign-sha-256-sbom-slsa)).
- **Homebrew (macOS & Linux):** `brew install devel0mer/tap/nhilens`
- **Scoop (Windows):** `scoop bucket add devel0mer https://github.com/devel0mer/scoop-bucket && scoop install devel0mer/nhilens`
- **Docker (GHCR — distroless, non-root, multi-arch):** `docker run --rm ghcr.io/devel0mer/nhilens:latest demo --no-write`
- **From source (requires Go 1.26+):** `CGO_ENABLED=0 go install github.com/devel0mer/nhilens/cmd/nhilens@latest`

---

## What It Checks

- **Honest AI agent vs. automation heuristics**: Scores 7 configurable signals (tags, names, service/OIDC trusts, programmatic keys, AI/LLM permissions & runtime calls like `bedrock`/`sagemaker`/`q`, and CloudTrail `userAgent` traces) and lists every matched signal. Generic CI/automation roles are labeled `automation` and capped at `45%` (`possible`) so ordinary CI bots do not false-positive as `likely` AI agents.
- **8 built-in risk rules (`R1–R8`)**: Wildcard admin (`R1`), unused permissions (`R2`), missing owner (`R3`), stale/multi-IP shared keys (`R4`), loose cross-account/OIDC trusts (`R5`), privilege escalation paths (`R6`), sensitive service wildcards (`R7`), and key hygiene (`R8`) — intersecting explicit Denies, IAM permissions boundaries, and optional `--scp-file` SCPs. See [docs/rules.md](docs/rules.md).
- **Built for CI & drift tracking**: Local SQLite history (`nhilens diff --fail-on-new high`), SARIF 2.1.0 for GitHub Code Scanning, `.nhilens-ignore.yaml` time-bounded waivers, and offline HTML/JSON/Markdown/CSV reports. Full CLI flags, multi-account profile loop, and config docs live in [docs/usage.md](docs/usage.md).

### Where `nhilens` Fits

| Tool | Primary Strength | Where `nhilens` Fits |
|---|---|---|
| **Prowler / ScoutSuite** | Broad multi-service cloud posture & CIS/compliance benchmarks | Use those for account-wide compliance; use `nhilens` to inventory non-human/AI identities, surface ownership gaps, and rank AI-capable roles |
| **Cloudsplaining** | Deep per-action IAM policy analysis | Use Cloudsplaining for exhaustive policy action triage; use `nhilens` to correlate policies, AI service usage, trusts, Access Advisor, and CloudTrail per identity |
| **PMapper** | Graph-based multi-hop IAM privilege escalation path solving | Use PMapper for transitive escalation graphs; use `nhilens` for fast, zero-dependency, offline snapshots centered on AI-agent ownership and blast radius |

---

## Roadmap

### `v0.3` (Next) — Multi-Account & Multi-Region
- **Native AWS Organizations scanning**: Built-in `organizations:ListAccounts` + read-only cross-account `AssumeRole` orchestration, org-wide rollup reports, and automatic SCP discovery (eliminating the manual `--scp-file` and shell profile loop).
- **Multi-region CloudTrail aggregation**: Fan-out across active regions (`--regions` / all enabled regions) so `userAgent` traces, 30d activity, and R4 multi-IP access keys are correlated account-wide in a single scan.

### Beyond `v0.3`
- Expanded detection profiles for emerging MCP servers, Bedrock AgentCore / Strands, and cross-account tool-invocation patterns.

*(Need multi-account scans today? See the [temporary profile-loop recipe](docs/usage.md#scanning-multiple-accounts--regions-temporary-profile-loop).)*

---

## Limitations & Sensitive Data

> **Review before sharing:** `nhilens.db` (created `0600`) and generated reports contain AWS account IDs, IAM ARNs, tags, policy metadata, and best-effort CloudTrail source IPs. Keep scan outputs out of version control and redact before sharing.

- **Single account & single-region CloudTrail (`v0.2.x`)**: `cloudtrail:LookupEvents` inspects `--region` only (up to 90 days of management events). Every CLI, HTML, Markdown, and SARIF output displays an explicit regional scope notice and structured scan `coverage` so partial data or regional limits are never mistaken for zero risk.
- **Effective permissions scope**: Evaluates attached managed, inline, and group policies intersected with explicit Denies, IAM permissions boundaries, and optional `--scp-file` SCPs. Resource-based policies (e.g., S3/KMS) and STS session policies are not evaluated.
- **Service-linked roles**: AWS-managed `/aws-service-role/` roles are inventoried but excluded from findings by default.
- **Non-goals**: Credential brokering/issuing, auto-remediation, web servers, or telemetry backends.

---

## Testing & License

```bash
CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test -count=1 ./...
```

To test end-to-end against an isolated **sandbox** AWS account (never production), see the guarded Terraform fixture in [test/sandbox-fixture/README.md](test/sandbox-fixture/README.md).

Licensed under Apache-2.0 ([LICENSE](LICENSE)). Embedded Cytoscape.js is MIT-licensed ([cytoscape.LICENSE.txt](internal/report/assets/cytoscape.LICENSE.txt)).
