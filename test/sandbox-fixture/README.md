# nhilens Sandbox Integration Fixture

> **SANDBOX ONLY — NEVER APPLY TO PRODUCTION.**
> This Terraform configuration creates **5 deliberately weak IAM identities** (one per MVP risk rule) to validate `nhilens scan` and `nhilens report` against a real AWS sandbox account. It is **never** executed automatically in CI.

## Safety Guardrails Built In

- `confirm_sandbox_account` defaults to `false`; Terraform refuses to run unless you pass `-var="confirm_sandbox_account=true"`.
- Optional `expected_account_id` locks execution to a specific 12-digit sandbox account ID.
- The **R1** `AdministratorAccess` role carries a `sts:GetCallerIdentity`-only permissions boundary so it cannot mutate AWS resources even in a sandbox, while still triggering R1 and exercising `nhilens`'s permissions-boundary visibility.
- The **R4** secret access key is never printed in Terraform outputs (and Terraform state is ignored by `.gitignore`).
- All created resources are free-tier IAM entities (no billable AWS infrastructure).

## Fixture Mapping (One Identity per Rule)

| Fixture Resource | Identity Type | Target Rule | Expected Signals |
|---|---|---|---|
| `nhilens-sandbox-bedrock-admin-agent` | Role | **R1** `wildcard-permissions` | `AdministratorAccess` + `bedrock.amazonaws.com` trust + `agent=true` + permissions boundary note |
| `nhilens-sandbox-unused-agent-role` | Role | **R2** `unused-permissions` | Unused `AmazonS3ReadOnlyAccess` & `AmazonEC2ReadOnlyAccess` (note: newly created role age note included) |
| `nhilens-sandbox-orphan-bot-role` | Role | **R3** `no-owner` | Missing `owner`/`sponsor` tag + `ecs-tasks.amazonaws.com` trust + `bot` name |
| `nhilens-sandbox-ci-bot-user` + key | User + Key | **R4** `stale-or-shared-key` | Programmatic IAM user (no console login) with active static access key (see R4 validation tip below) |
| `nhilens-sandbox-gh-wildcard-deploy` | Role | **R5** `loose-trust` | GitHub Actions OIDC trust with wildcard `sub = "repo:nhilens-sandbox-nonexistent-org/*:*"` |

## Prerequisites

- Terraform `>= 1.5.0`
- An isolated AWS sandbox account and credentials configured via `--profile` or AWS SSO

## Apply

```bash
cd test/sandbox-fixture
terraform init

# Preview changes first (lock to your sandbox account ID for extra safety)
terraform plan \
  -var="confirm_sandbox_account=true" \
  -var="expected_account_id=123456789012" \
  -var="aws_profile=sandbox" \
  -var="aws_region=us-east-1"

# Apply to the sandbox account
terraform apply \
  -var="confirm_sandbox_account=true" \
  -var="expected_account_id=123456789012" \
  -var="aws_profile=sandbox" \
  -var="aws_region=us-east-1"
```

> **Note:** If your sandbox account already has an IAM OIDC provider for `https://token.actions.githubusercontent.com`, pass `-var="github_oidc_provider_arn=arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"` so Terraform reuses it instead of creating a duplicate.

## Validate with `nhilens`

```bash
# Build nhilens from the repository root
cd ../..
CGO_ENABLED=0 go build -o ./nhilens ./cmd/nhilens

# Run a strictly read-only scan against the sandbox account
./nhilens scan --profile sandbox --region us-east-1 --since 7d --out ./nhilens-out

# Generate the standalone HTML report (offline Cytoscape.js graph)
./nhilens report --in ./nhilens-out/nhilens.db --out ./nhilens-out/report.html
```

### Validating R4 (`stale-or-shared-key`) on a freshly created key
Because `nhilens-sandbox-ci-bot-user`'s access key is brand new when first applied:
- It immediately exercises programmatic-user agent detection (`HasConsoleLogin=false` + access key) and `user → key` graph edges.
- To verify **R4** via key age after 1+ day, copy `docs/nhilens.example.yaml` to a temporary config with `rules.key_max_age_days: 1` and pass `--config`.
- To verify **R4** via best-effort shared IPs, invoke `sts:GetCallerIdentity` with the sandbox key from two distinct source networks (wait ~5–15 minutes for CloudTrail Event History indexing) and re-run `nhilens scan`.

## Destroy (Always Clean Up!)

Always tear down the sandbox fixtures as soon as validation is complete:

```bash
cd test/sandbox-fixture
terraform destroy \
  -var="confirm_sandbox_account=true" \
  -var="expected_account_id=123456789012" \
  -var="aws_profile=sandbox" \
  -var="aws_region=us-east-1"
```

Remember to also delete any local `nhilens-out/` database/reports and Terraform `.tfstate` files when finished.
