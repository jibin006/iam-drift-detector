# Architecture Decision Records

---

## ADR-001: Customer-Managed Policies Only — Not AWS-Managed

**Status**: Accepted

### Context

AWS accounts have two policy scopes:
- **AWS-managed policies** (`arn:aws:iam::aws:policy/...`) — maintained by AWS, versioned, documented
- **Customer-managed policies** (`arn:aws:iam::<account-id>:policy/...`) — created by the account owner

`list_policies` returns both by default unless filtered with `Scope="Local"`.

### Decision

Scan customer-managed only (`Scope="Local"`).

### Reasoning

AWS-managed policies are AWS's problem to audit. `AdministratorAccess` contains `Action: *`, `Resource: *` — that's intentional. Scanning it produces a CRITICAL finding that is not actionable. It's noise.

Customer-managed policies are where drift happens. They're created by engineers, modified manually in the console, sometimes copy-pasted from Stack Overflow, and rarely reviewed after initial creation. That's the actual risk surface.

**Side effect**: This also reduces API call volume significantly. Accounts at medium-sized companies have hundreds of AWS-managed policies. Scanning all of them would hit throttle limits faster and add zero signal.

### Trade-offs Accepted

- Inline policies (directly attached to users/roles) are not customer-managed and are missed. Documented as open scope item in README.

---

## ADR-002: Multi-Signal Risk Detection Over Wildcard-Only

**Status**: Accepted

### Context

The original implementation detected two conditions:
- `Action` contains `"*"`
- `Resource` contains `"*"`

This misses a large class of dangerous IAM configurations.

### Decision

Implement 8 risk signal categories with structured severity scoring.

### Reasoning

**Privilege escalation paths are the real threat.** A policy with `iam:PassRole` and `ec2:RunInstances` can bootstrap admin access even if neither action looks alarming in isolation. An attacker with these two permissions can create an EC2 instance with an admin role attached — effectively giving themselves admin access without ever touching `Action: *`.

The OWASP-equivalent for IAM risk isn't "wildcards" — it's privilege escalation paths, logging suppression, and missing condition constraints. Wildcard detection is the easiest-to-see tip of the iceberg.

**Specific gaps in wildcard-only detection:**

| Risk | Detectable by wildcard scan | Detectable by multi-signal |
|---|---|---|
| `Action: iam:*` (full IAM control) | ✓ | ✓ |
| `iam:PassRole` + `ec2:RunInstances` | ✗ | ✓ |
| `cloudtrail:StopLogging` without condition | ✗ | ✓ |
| `iam:DeleteUser` without MFA condition | ✗ | ✓ |
| `sts:AssumeRole` with `Resource: *` | ✗ | ✓ |
| `s3:GetObject` with `Resource: *` | ✗ (only Resource: * flagged, not the action+resource combination significance) | ✓ |

### Trade-offs Accepted

- Multi-signal detection has higher FP potential than wildcard-only. A policy with `iam:PassRole` for a legitimate data pipeline is flagged as CRITICAL. Engineers must review findings, not auto-remediate. The tool produces findings for human review, not automated policy modification.
- Detection logic is more complex — more code to maintain, more edge cases to test.

---

## ADR-003: Gemini vs Bedrock for AI Explanation

**Status**: Accepted (with documented data privacy caveat)

### Context

Two primary options for AI-powered policy explanation:
1. **Google Gemini** (external API, `google.generativeai` SDK)
2. **AWS Bedrock** (in-account, VPC-native, AWS IAM-controlled)

### Decision

Gemini via external API, with explicit documentation of the data privacy trade-off.

### Reasoning

**Bedrock operational cost in this context:**

Bedrock requires:
- Per-region model access approval (console action, not automatable via IaC initially)
- Bedrock invocation permissions in the scanner's IAM role
- If the scanner runs cross-account, cross-account Bedrock access or per-account role configuration
- VPC endpoint for private access (adds cost and networking configuration)

For a scanning tool intended to run across multiple AWS accounts, Bedrock's IAM-native access model becomes a bootstrapping problem: the scanner needs permission to call Bedrock in each target account, which requires IAM changes in each target account before the scanner can run.

Gemini: single API key, works from any environment, no per-account configuration.

**Data privacy trade-off:**

IAM policy content (action lists, resource ARNs, condition keys) is sent to Google's API. This is the genuine downside. Mitigations applied:
- Policy ARNs are stripped before sending to Gemini (no account ID in the payload)
- Only the policy document structure is sent, not the principal attachments
- Gemini API data handling: not used for training by default on paid tier

**When to flip this decision:** If deploying in a regulated environment (financial services, healthcare) where policy content is considered sensitive metadata, switch to Bedrock with VPC endpoint. The `GeminiExplainer` class is isolated behind an `Explainer` interface — swap implementation without touching the rest of the pipeline.

### Trade-offs Accepted

- IAM policy data leaves the AWS account boundary (mitigated but not eliminated)
- Gemini API availability is not AWS SLA — if Gemini is down, explanations fail (but findings are still generated; explanation is non-blocking)
- Gemini rate limits are per API key, not per IAM role — shared key = shared throttle

---

## ADR-004: Baseline Stored as JSON, Not in DynamoDB or S3

**Status**: Accepted

### Context

Drift detection requires a "known good" baseline — what IAM state *should* look like. Options for storing the baseline:
1. **Flat JSON file** — checked into git alongside IaC
2. **S3 object** — stored in a bucket, versioned
3. **DynamoDB table** — queried at scan time

### Decision

JSON file, checked into git.

### Reasoning

The baseline should be treated as code. It describes the expected state of IAM — that's the same category of artifact as Terraform state. If it lives in a database, it can be modified outside of a code review. If it's in git, every change is a commit with an author, timestamp, and diff.

The workflow: Terraform apply → regenerate baseline JSON → commit alongside the Terraform change. The baseline is never edited directly — it's always regenerated from the authoritative IaC state.

**Practical implication**: drift detection runs in CI/CD as a post-apply step. The baseline JSON in the repo represents the last known-good Terraform state. Any manual console changes to IAM will produce a drift finding on the next CI run.

### Trade-offs Accepted

- Large accounts (hundreds of customer-managed policies) produce large baseline JSON files. Git history on a frequently-changing baseline can get noisy. Mitigation: baseline JSON should be generated from a policy inventory script tied to the Terraform pipeline, not hand-edited.

---

## ADR-005: Exponential Backoff on IAM API Calls

**Status**: Accepted

### Context

AWS IAM API is rate-limited. `list_policies`, `get_policy`, and `get_policy_version` all have throttle limits. Scanning 300+ policies in a tight loop reliably hits `ThrottlingException`.

### Decision

Configure boto3 client with `Config(retries={"max_attempts": 10, "mode": "adaptive"})`. This enables adaptive retry mode, which uses exponential backoff with jitter.

### Reasoning

Without this, the original implementation silently failed on throttle: the exception was caught at the policy level (which continued the loop) but the policy was skipped without recording it as a scan failure. The result: the tool reported "0 risky policies" for an account where it had actually only scanned the first 50 policies before hitting throttle.

That's a false negative at the tool level — not just a missing finding but a misleading summary. "0 risky policies found" when you only scanned 50 of 300 is worse than an error.

**Adaptive vs Standard mode**: Standard retry uses fixed backoff intervals. Adaptive mode uses AWS's token bucket algorithm — it backs off when it detects the account is throttled and accelerates when capacity is available. Better throughput on large accounts.

### Trade-offs Accepted

- Adaptive retry can significantly extend scan time on accounts that are heavily throttled. A scan that takes 8 seconds at normal throughput might take 3+ minutes if the account is under heavy API load from other tools. The scanner should surface total scan time in the report for operational awareness.
