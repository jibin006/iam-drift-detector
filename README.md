# IAM Drift Detector

Detects IAM policy risk and configuration drift in AWS accounts. Two distinct capabilities in one pipeline:

1. **Risk analysis** — scans customer-managed IAM policies for dangerous permission patterns beyond just `Action: *`. Catches privilege escalation paths, service-level wildcards, logging suppression, and missing condition constraints on sensitive actions.

2. **Drift detection** — compares live IAM state against a stored baseline (your Terraform-generated snapshot). Flags policies that exist in AWS but not in IaC, and policies where live permissions exceed what IaC defined. This is the actual "drift" — the gap between what your code declares and what AWS is enforcing.

The original version of this tool was only doing #1 (badly — only `Action: *`). Drift detection was in the name but not the code. See `FAILURES.md FAIL-001`.

---

## Why This Exists

IAM is the control plane. If IAM is wrong, everything downstream is wrong — it doesn't matter how hardened your compute or storage is. The problem isn't that teams set `Action: *` intentionally. It's that:

- IAM policies drift from what Terraform declares — someone makes a manual change in console, it's never caught
- Risk detection tools only look for obvious wildcards, not privilege escalation paths like `iam:PassRole` + `ec2:RunInstances`
- When a risky policy is found, engineers get a JSON blob with no context on blast radius or remediation path

This tool closes those three gaps: catches the drift, catches the non-obvious risks, and uses an AI explainer to produce actionable findings instead of raw policy dumps.

---

## What Gets Detected

### Risk Categories

| Category | Example Pattern | Severity |
|---|---|---|
| Full admin wildcard | `Action: *` + `Resource: *` | CRITICAL |
| Service-level wildcard | `Action: iam:*` or `Action: s3:*` | HIGH |
| Privilege escalation path | `iam:PassRole` + `iam:CreateRole` or `ec2:RunInstances` | CRITICAL |
| Logging suppression | `cloudtrail:StopLogging` or `cloudtrail:DeleteTrail` | HIGH |
| Missing MFA condition | `iam:DeleteUser` without `aws:MultiFactorAuthPresent` condition | HIGH |
| Unrestricted STS assume | `sts:AssumeRole` with `Resource: *` and no condition | HIGH |
| S3 unrestricted read | `s3:GetObject` with `Resource: *` and no condition | MEDIUM |
| Resource wildcard only | `Action: s3:PutObject`, `Resource: *` | MEDIUM |

The original tool only caught `Action: *` and `Resource: *`. Everything else in this table was a blind spot. See `FAILURES.md FAIL-002`.

### Drift Categories

| Drift Type | What It Means |
|---|---|
| `POLICY_ADDED` | Policy exists in AWS but not in IaC baseline — unmanaged, out of version control |
| `POLICY_REMOVED` | Policy in IaC baseline is gone from AWS — deletion not tracked |
| `PERMISSIONS_EXPANDED` | Live policy has actions/resources not present in baseline |
| `PERMISSIONS_REDUCED` | Live policy is more restrictive than baseline — usually fine, but track it |
| `CONDITION_REMOVED` | Baseline had a condition constraint; live policy dropped it — blast radius expanded |

---

## Architecture

```
AWS Account
      │
      ▼
IAM Scanner (boto3 paginator)
      │  • Customer-managed policies only
      │  • Paginated — handles accounts with 500+ policies
      │  • Exponential backoff on throttle
      │
      ├──────────────────────────────────────┐
      ▼                                      ▼
Risk Analyzer                        Drift Comparator
      │  • 8 risk signal categories          │  • Load IaC baseline JSON
      │  • Severity scoring (CVSS-style)     │  • Structural diff per policy
      │  • Privilege escalation graph        │  • Condition constraint tracking
      │                                      │
      └──────────────┬───────────────────────┘
                     ▼
             Finding Aggregator
                     │  • Deduplicates overlapping signals
                     │  • Ranks by blast radius
                     │
                     ▼
             AI Explainer (Gemini)
                     │  • Per-finding explanation + remediation
                     │  • Policy data stays in your account's API call
                     │  • Batched to stay within rate limits
                     │  ⚠ See DECISIONS.md ADR-003 on data privacy trade-off
                     │
                     ▼
             JSON Report + Console Summary
```

---

## Measured Results

Run against a test account with 23 customer-managed policies:

| Metric | Value |
|---|---|
| Policies scanned | 23 |
| Policies with findings | 7 |
| Risk findings total | 14 |
| Drift findings total | 3 |
| Wildcard-only detection (old) | 4 findings |
| Multi-signal detection (current) | 14 findings |
| Scan time (23 policies) | ~8 seconds |
| AI explanation time | ~2-4 seconds per finding |

The old wildcard-only logic missed 10 of the 14 findings. The 10 missed findings included two privilege escalation paths and one condition removal that eliminated MFA enforcement on IAM delete operations. That's the gap that matters.

---

## Key Design Decisions

Full reasoning in [`DECISIONS.md`](./DECISIONS.md). Short version:

**Why Gemini and not Bedrock**: Bedrock requires per-region model access approval and VPC endpoint configuration. For a security scanning tool that runs against cross-account targets, Bedrock adds IAM complexity (model invocation permissions per account). Gemini is a single API key. The trade-off is that IAM policy content is sent to Google — see `DECISIONS.md ADR-003` for how this is handled.

**Why customer-managed policies only**: AWS-managed policies are versioned and audited by AWS — scanning them produces noise and no actionable findings. Customer-managed policies are the actual risk surface.

**Why pagination matters**: `list_policies` is paginated at 100 policies per page. An AWS account with 300+ customer-managed policies (common at mid-size companies) hits this limit on first call. The original code didn't paginate. This was silent data loss — the tool appeared to work but only scanned the first 100 policies. See `FAILURES.md FAIL-003`.

**Why exponential backoff**: IAM API calls are rate-limited. Scanning hundreds of policies in a tight loop hits `ThrottlingException`. Without backoff, the scan silently fails on page 2+. Boto3's built-in retry config handles this — but only if you configure it. Default client has no retry on throttle.

---

## What This Doesn't Catch

- **Role trust policies** — who can assume a role is not covered; separate scanner needed
- **Service Control Policies (SCPs)** — organization-level controls; requires different API scope
- **Inline policies** — attached directly to users/roles, not customer-managed; `list_policies` doesn't return these
- **Resource-based policies** — S3 bucket policies, KMS key policies, Lambda resource policies
- **Permission boundaries** — whether a permission boundary is in place affects actual effective permissions

These are documented as open scope items, not bugs. A complete IAM audit pipeline would chain this tool with role trust analysis and SCP evaluation.

---

## Quick Start

```bash
pip install -r requirements.txt

# Set credentials
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
export GEMINI_API_KEY=...

# Run risk scan only
python main.py --mode risk

# Run drift detection against a baseline
python main.py --mode drift --baseline baselines/prod-baseline.json

# Run both
python main.py --mode full --baseline baselines/prod-baseline.json

# Generate a new baseline from current state (store this in git, treat it as IaC)
python main.py --mode baseline --output baselines/prod-baseline.json
```

---

## Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion"
      ],
      "Resource": "*"
    }
  ]
}
```

Read-only. The scanner never writes, modifies, or creates IAM resources.

---

## Running Tests

```bash
python -m pytest tests/ -v
# Tests run against synthetic policy documents — no AWS credentials required
```

---

## Failure Log

What broke during build and what it revealed — see [`FAILURES.md`](./FAILURES.md).

---

## Threat Model

What this tool is trying to detect and where it's blind — see [`docs/threat-model.md`](./threat-model.md).
