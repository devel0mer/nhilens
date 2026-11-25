# nhilens Risk Rules & Scoring Reference

Every risk rule in `nhilens` implements the common `rules.Rule` interface ([internal/rules/rule.go](../internal/rules/rule.go)) and emits findings with a stable ID, severity, explanation, remediation hint, and concrete evidence.

## Scope & Guardrails

- **Non-human identities**: Rules evaluate IAM roles, access keys, and IAM users that lack a console login profile, hold access keys, have agent-detection signals, or whose login profile could not be determined. Console-only human IAM users with no access keys and no agent signals are excluded.
- **Service-linked roles**: AWS-managed `/aws-service-role/` roles are inventoried and labeled (`is_service_linked_role: true`) but excluded from findings by default to avoid noise. Opt in via `--include-service-linked-roles` or `rules.include_service_linked_roles: true` in `nhilens.yaml`.
- **Rule toggles**: Any rule can be enabled or disabled individually under `rules.enabled` in `nhilens.yaml`.

---

## Built-In Rules (R1–R8)

Run `nhilens explain` in your terminal to list all rules, or `nhilens explain <RULE_ID>` (e.g., `nhilens explain R6`) for copy-pasteable AWS CLI and Terraform remediation templates.

### R1 — `wildcard-permissions`
- **Severity**: `critical` (unconditioned full/admin control) or `high` (conditioned wildcards)
- **Applies to**: Non-human `role` and `user` identities (access keys are not double-flagged; their parent user is evaluated).
- **Triggers when**:
  - **`critical`**:
    - AWS-managed `AdministratorAccess` is attached directly or inherited via an IAM group, **or**
    - An **unconditioned** `Allow` statement grants `Action: "*"` (or `"*:*"`), `NotAction` (without `Action`), or `iam:*` on `Resource: "*"`.
  - **`high`**:
    - Any of the admin-equivalent wildcard statements above **with a `Condition` block** (severity is reduced from `critical` to `high`, and the condition keys are listed in evidence so conditioned wildcards do not produce blind critical alerts).
- **Nuance & context**:
  - Explicit IAM escalation paths (`iam:PassRole`, `sts:AssumeRole`, `iam:AttachRolePolicy`, etc.) are evaluated cleanly by **R6** without duplicate scoring.
  - Scoped service wildcards (e.g., `s3:*`), `Action: "*"` restricted to a specific resource ARN, and `Deny` statements do not trigger R1.
  - If an IAM permissions boundary is attached or an optional `--scp-file` JSON guardrail is provided, R1 intersects them against admin-wildcard statements: when the guardrail caps full wildcard access (`Action: "*"` / `iam:*`), R1 downgrades the finding to `medium` and records the capping guardrail in evidence. Full action-level SCP/boundary intersections, resource policies, and session policies are not evaluated.
- **Remediation**: Replace `AdministratorAccess`, `NotAction`, `iam:*`, or wildcard `Action`/`Resource` statements with least-privilege policies scoped to specific actions and ARNs, and attach a permissions boundary where appropriate.

### R2 — `unused-permissions`
- **Default severity**: `medium`
- **Applies to**: Non-human `role` and `user` identities.
- **Triggers when**: IAM Access Advisor (`GenerateServiceLastAccessedDetails` / `GetServiceLastAccessedDetails`) reports one or more granted AWS services that were never authenticated or not authenticated within `rules.stale_days` (default `90`).
- **Nuance & context**:
  - Skipped cleanly without false positives when Access Advisor data is absent (e.g., `--skip-service-last-accessed` or an async job timeout/failure).
  - If an identity was created more recently than `rules.stale_days`, unused services are still reported alongside an explicit age-context note.
  - AWS Access Advisor tracks the trailing 400 days and may lag slightly.
- **Config knobs**: `rules.stale_days` (default `90`), `rules.enabled.R2`.
- **Remediation**: Trim attached and inline policies to remove unused AWS services.

### R3 — `no-owner`
- **Default severity**: `medium`
- **Applies to**: Taggable non-human `role` and `user` identities (access keys cannot carry IAM tags independently of their parent user in AWS).
- **Triggers when**: None of the configured `agent_detection.owner_tag_keys` (default: `owner`, `sponsor`, `team`, `maintainer`, `created-by`, matched case-insensitively) has a non-empty value on the identity.
- **Config knobs**: `agent_detection.owner_tag_keys`, `rules.enabled.R3`.
- **Remediation**: Tag the IAM role or user with an accountable owner or team (`aws iam tag-role` / `aws iam tag-user`).

### R4 — `stale-or-shared-key`
- **Default severity**: `high`
- **Applies to**: `key` identities (static IAM user access keys).
- **Triggers when**:
  - **Stale key**: Key age exceeds `rules.key_max_age_days` (default `90`), **and/or**
  - **Shared key (best-effort)**: CloudTrail management events show the key used from `>= rules.min_shared_key_ips` (default `2`) distinct valid IPv4/IPv6 source addresses (non-IP AWS service strings such as `AWS Internal` are ignored).
- **Nuance & context**: Multi-IP detection is explicitly labeled **best-effort**. NAT gateways, corporate egress proxies, or ephemeral CI runners can legitimately emit multiple source IPs for a single workload. Additionally, CloudTrail `LookupEvents` is **regional** — events from regions other than `--region` are not visible in a single regional scan.
- **Config knobs**: `rules.key_max_age_days` (default `90`), `rules.min_shared_key_ips` (default `2`), `rules.enabled.R4`.
- **Remediation**: Replace static access keys with short-lived STS credentials via IAM roles (OIDC, EC2/ECS/Lambda task roles). Where keys remain necessary, rotate them regularly, dedicate one key per workload, and delete stale/inactive keys.

### R5 — `loose-trust`
- **Severity**: `critical`, `high`, or `medium` (highest triggered sub-check on the role)
- **Applies to**: `role` identities (`AssumeRolePolicyDocument` `Allow` statements).
- **Triggers when**:
  - **`critical`**:
    - `Principal: "*"` or `Principal: {"AWS": "*"}` lacks a concrete `aws:PrincipalOrgID` or `aws:PrincipalAccount` condition, **or**
    - GitHub Actions, GitLab, or EKS IRSA OIDC trust has no `:sub` condition, **or**
    - Cognito Identity federation (`cognito-identity.amazonaws.com`) lacks a concrete `cognito-identity.amazonaws.com:aud` identity pool ID condition.
  - **`high`**:
    - Cross-account `AWS` principal (different 12-digit account ID than the scanned account) lacks a concrete `sts:ExternalId` (or `aws:PrincipalOrgID`) condition, **or**
    - GitHub Actions, GitLab, or EKS IRSA OIDC uses wildcards (`*`, `?`) in `:sub` or omits/wildcards `:aud`, **or**
    - Cognito Identity federation does not restrict `cognito-identity.amazonaws.com:amr` to `authenticated`, **or**
    - SAML federation (`:saml-provider/`) lacks a concrete `SAML:aud` condition.
  - **`medium`**:
    - A configured confused-deputy-prone AWS service principal (`rules.confused_deputy_service_principals`, e.g., `bedrock.amazonaws.com`, `sagemaker.amazonaws.com`, `scheduler.amazonaws.com`, `events.amazonaws.com`, `codebuild.amazonaws.com`, `states.amazonaws.com`) lacks an `aws:SourceArn`, `aws:SourceAccount`, or `aws:SourceOrgID` condition.
- **Config knobs**: `rules.confused_deputy_service_principals`, `rules.enabled.R5`.
- **Remediation**: Restrict `Principal` to specific trusted ARNs/services; require `sts:ExternalId` on external cross-account trusts; pin both `sub` and `aud` (`sts.amazonaws.com`) for GitHub/GitLab/EKS OIDC; enforce `aud`/`amr` for Cognito and `SAML:aud` for SAML; and add `aws:SourceAccount` or `aws:SourceArn` on confused-deputy-prone service trusts.

### R6 — `privilege-escalation-path`
- **Severity**: `critical` (direct unconditioned IAM escalation or `iam:PassRole` + compute/AI launch) or `high` (conditioned escalation, standalone `iam:PassRole` on `*`, or `sts:AssumeRole` on `*`)
- **Applies to**: Non-human `role` and `user` identities.
- **Triggers when**:
  - Explicit IAM mutation/credential actions (`iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:AttachRolePolicy`, `iam:AttachUserPolicy`, `iam:AttachGroupPolicy`, `iam:PutRolePolicy`, `iam:PutUserPolicy`, `iam:PutGroupPolicy`, `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `iam:UpdateAssumeRolePolicy`, `iam:AddUserToGroup`) on `Resource: "*"`
  - `iam:PassRole` on `Resource: "*"` without `iam:PassedToService` (escalates to `critical` if paired with compute/AI launch actions like `lambda:CreateFunction`, `ec2:RunInstances`, `ecs:RunTask`, `bedrock:CreateAgent`, `sagemaker:CreateNotebookInstance`, `codebuild:CreateProject`)
  - `sts:AssumeRole` on `Resource: "*"` (unbounded role chaining)
- **Guardrails**: Ignores full `Action: "*"` / `iam:*` statements already caught by R1 so admin roles are not double-scored.
- **Config knobs**: `rules.enabled.R6`.

### R7 — `sensitive-service-wildcard`
- **Severity**: `high` (unconditioned) or `medium` (conditioned)
- **Applies to**: Non-human `role` and `user` identities.
- **Triggers when**: Unconditioned `Resource: "*"` allows broad secret/key access (`kms:*`, `kms:Decrypt`, `secretsmanager:*`, `secretsmanager:GetSecretValue`, `ssm:*`, `ssm:GetParameter*`) or unrestricted AI control planes (`bedrock:*`, `sagemaker:*`).
- **Guardrails**: Ignores full `Action: "*"` statements already covered by R1.
- **Config knobs**: `rules.enabled.R7`.

### R8 — `key-hygiene`
- **Default severity**: `medium`
- **Applies to**: `user` and `key` identities.
- **Triggers when**:
  - An IAM user holds **2 or more Active** access keys simultaneously, **or**
  - An **Active** access key older than 7 days has **never been used**.
- **Config knobs**: `rules.enabled.R8`.

---

## Heuristic Agent vs. Automation Detection (Weighted 0–100% Confidence)

`nhilens` computes a transparent `agent_confidence` score (`0–100%`), classifies `workload_kind` (`ai_agent` vs `automation`), and maps confidence to `agent_likelihood` (`none` = 0%, `possible` = 1–49%, `likely` = 50–100%) using **7 configurable signal sources** in `nhilens.yaml`:

| # | Signal Source | Class | Weight | Default Configuration |
|---|---|---|---|---|
| 1a | **AI-specific tags** | `ai_agent` | **`+35`** | Tag keys (`agent`, `ai`, `ai-agent`) or `workload-type`/`automation` whose value contains an AI token, or tag value tokens (`agent`, `ai`, `llm`, `mcp`, `autonomous`); falsy values (`false`, `0`, `no`, `none`, `off`) ignored |
| 1b | **General automation tags** | `automation` | **`+20`** | Tag keys `automation`/`workload-type` with non-AI values, or tag value tokens `bot`/`automation` |
| 2a | **AI-specific name tokens** (`ai_name_tokens`) | `ai_agent` | **`+25`** | Delimiter-bounded tokens: `agent`, `agents`, `ai`, `llm`, `bedrock`, `mcp`, `copilot`, `rag`, `claude`, `gpt`, `gemini`, `openai`, `anthropic`, `langchain`, `strands`, `crewai`, `autogen` (evaluated independently of `role_name_patterns`; customize in `nhilens.yaml` for org terms like `assistant`). Known infrastructure prefixes in `ai_name_exclusions` (`jenkins`, `buildkite`, `teamcity`, `datadog`, `ssm`, `codedeploy`, `cloudwatch`, `splunk`, `newrelic`, `dynatrace`, `grafana`, `otel`, `prometheus`, `zabbix`, `fluentd`, `fluentbit`, `filebeat`, `vault`, `consul`, `puppet`, `chef`, `wazuh`, `crowdstrike`) suppress generic `agent`/`agents` AI attribution and downgrade them to automation (`+20`) unless an unambiguous AI token also matches |
| 2b | **General automation name patterns** (`role_name_patterns` & excluded infra agents) | `automation` | **`+20`** | Delimiter-bounded regex: `bots?`, `auto`, `automation`, `pipeline`, `deploy`, `ci`, `cd`, `worker`, `runner`, or an `ai_name_exclusions` infrastructure agent (only adds points when no `ai_name_tokens` match already scored the name) |
| 3a | **AI service principal trusts** | `ai_agent` | **`+35`** | `bedrock.amazonaws.com`, `sagemaker.amazonaws.com` (when present in `automation_service_principals`) |
| 3b | **Other automation service principal trusts** | `automation` | **`+25`** | Remaining `automation_service_principals`: `lambda`, `ecs-tasks`, `codebuild`, `codepipeline`, `states`, `scheduler`, `events` |
| 4 | **OIDC / workload federation hints** (`oidc_provider_hints`) | `automation` | **`+25`** | `token.actions.githubusercontent.com`, `gitlab.com`, `oidc.eks.`, `accounts.google.com` |
| 5 | **Programmatic IAM users** | `automation` | **`+25`** | Access keys present with no console login profile (propagated to child `key` identities) |
| 6 | **AI/LLM service capability & runtime activity** (`ai_service_namespaces`) | `ai_agent` | **`+30`** policy / **`+35`** runtime / **`+45`** both | `bedrock`, `bedrock-runtime`, `bedrock-agent`, `bedrock-agent-runtime`, `bedrock-agentcore`, `sagemaker`, `sagemaker-runtime`, `q`, `qbusiness` (does not trigger merely from `Action: "*"`) |
| 7a | **CloudTrail AI framework `userAgent`** (`ai_framework_user_agents`) | `ai_agent` | **`+40`** | `langchain`, `langgraph`, `strands`, `crewai`, `autogen`, `llamaindex`, `mcp`, `bedrock-agent`, `claude`, `anthropic`, `openai` (scoped to scanned `--region`) |
| 7b | **CloudTrail generic AWS SDK `userAgent`** (`sdk_user_agents`) | `automation` | **`+15`** | `boto3`, `botocore`, `aws-sdk-` (when no AI framework trace matched; scoped to scanned `--region`) |

**Anti-false-positive guardrail (`automation` cap):** Ordinary CI/CD users or OIDC deploy roles (for example, a programmatic IAM user named `ci-bot` with access keys and no console login: `+20` automation name + `+25` programmatic user = `45%`) carry general automation signals only. Without at least one `ai_agent` signal, `nhilens` labels them `workload_kind: "automation"` and caps `agent_confidence` at **`45%` (`possible`)** so they never trigger `agent_likelihood: "likely"` or the `+1.5` AI agent risk bonus.

**High-signal profile correlation:** Matching a known workload profile (`bedrock-agent`, `lambda-ai-invoker`, `mcp-or-framework-agent`, `ci-oidc-automation`, `programmatic-key-bot`) records `agent_profile` and adds a **`+10`** confidence bonus **only when at least one AI-specific signal is present**. Every identity lists the exact matched signals (`agent_reasons`), matched `ai_services`, and a 30-day regional CloudTrail activity summary (`activity_30d`).

---

## Risk Scoring (0–10)

Weights and curve parameters live in one config section (`scoring` in `nhilens.yaml`):

| Factor | Default Weight |
|---|---|
| `critical` finding | `+4.0` |
| `high` finding | `+3.0` |
| `medium` finding | `+2.0` |
| `low` finding | `+1.0` |
| `info` finding | `+0.5` |
| **Compound blast radius** (`R1`/`R6` high/critical **+** `R5` high/critical) | `+2.0` |
| `agent_likelihood == likely` bonus *(when ≥ 1 finding exists)* | `+1.5` |
| `max_score` | `10.0` |
| `saturation_scale` | `6.5` |

To preserve separation among heavily misconfigured identities (instead of clipping flat at `10.0`), raw weighted points map monotonically onto `[0, max_score]` via:

```text
risk_score = max_score * (1 - exp(-raw_risk_points / saturation_scale))
```

Example progression with defaults (`saturation_scale = 6.5`):
- Clean identity (even if `likely` agent): `raw 0.0` → **`0.0 / 10`**
- 1 `medium`: `raw 2.0` → **`2.6 / 10`**
- 1 `high`: `raw 3.0` → **`3.7 / 10`**
- 1 `critical`: `raw 4.0` → **`4.6 / 10`**
- 1 `critical` + `likely` agent bonus: `raw 5.5` → **`5.7 / 10`**
- 2 `critical` + `likely` agent bonus: `raw 9.5` → **`7.7 / 10`**
- 2 `critical` + 2 `medium` + `likely` agent bonus: `raw 13.5` → **`8.7 / 10`**
- All 5 rules severe + `likely` agent bonus: `raw 16.5` → **`9.2 / 10`**

Every scored identity stores both `raw_risk_points` and itemized `score_contributions` for full explainability.
