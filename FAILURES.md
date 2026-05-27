# Failure Log

What broke during build, what assumption was wrong, and what changed. Not a bug list — a record of where the mental model failed.

---

## FAIL-001: The Tool Was Not a Drift Detector

**When**: Initial design review after writing the first version  
**Symptom**: Tool named "IAM Drift Detector," README described drift detection, but the code only scanned for risky permissions. Drift — comparing live state against expected state — was never implemented.  
**Root cause assumption**: "Drift detection" and "risk detection" were treated as synonyms. They aren't. Risk detection finds dangerous policies. Drift detection finds policies that have changed from what your IaC defines. A policy can be risky but not drifted (it was always risky, it's in Terraform that way). A policy can be drifted but not risky (someone manually tightened a permission — a drifted but less-risky state).  
**What changed**: Split into two distinct capabilities. Risk analyzer handles static analysis of policy documents. Drift comparator handles comparison against a stored baseline. Both run in the same pipeline but produce separate finding types.  
**What this revealed**: Naming drives design. Calling it a "drift detector" when it was a "risk scanner" meant the actual drift problem — manual console changes escaping IaC — was never solved. The tool felt complete because the name was satisfied, but the problem it was named after wasn't being addressed.

---

## FAIL-002: Wildcard Detection Missed the Dangerous Policies

**When**: Testing against a real AWS account  
**Symptom**: Tool reported 4 risky policies. Manual review of the same account found 14 policies worth investigating. The 10 missed policies included:
- A policy with `iam:PassRole` + `ec2:RunInstances` (privilege escalation path)
- A policy with `cloudtrail:StopLogging` (logging suppression — an attacker's cover)
- A policy with `iam:DeleteUser` and no MFA condition (sensitive operation with no MFA enforcement)
- Two policies with `sts:AssumeRole` and `Resource: *` and no condition constraints

**Root cause**: Detection logic was `Action == "*"` or `Resource == "*"`. Service-level wildcards (`iam:*`, `s3:*`) and dangerous action combinations weren't in scope.  
**What changed**: Rewrote risk detection as a multi-signal analyzer with 8 risk categories. Each category has its own detection function, severity level, and justification. Added privilege escalation graph — checks for dangerous action combinations, not just individual actions.  
**What this revealed**: IAM risk is not a one-dimensional "wildcard or not" question. The most dangerous policies I've seen in production didn't have `Action: *`. They had specific actions that, in combination, allow admin escalation. Checking for wildcards alone gives false confidence.

---

## FAIL-003: Silent Data Loss from Missing Pagination

**When**: Running against an account with 180 customer-managed policies  
**Symptom**: Tool ran, reported "Analysis complete: 2/100 policies have risky permissions." Account actually had 180 policies — only the first 100 were ever analyzed.  
**Root cause**: `list_policies` returns 100 results per page by default. The original code iterated the first page and stopped. No pagination, no error — just silent truncation. The summary line printed "100 policies analyzed" which appeared correct until I manually checked the account's policy count.  
**What changed**: Replaced direct `list_policies` call with `iam.get_paginator("list_policies")`. Paginator handles the `Marker` token automatically. Added a scan summary that prints total policies found vs total policies scanned — if they don't match, it's a signal.  
**What this revealed**: Silent data loss is worse than an explicit error. An error tells you something went wrong. "100 policies analyzed" when there are 180 tells you everything went fine. The tool was producing a false assurance of complete coverage while only scanning 55% of the account.

---

## FAIL-004: ThrottlingException Silently Dropped Policies

**When**: Running against a large account simultaneously with other tooling  
**Symptom**: Some policies appeared in the scan results, others were missing. No errors in the output. On investigation, the inner `try/except ClientError` block was catching `ThrottlingException` and continuing — logging an error at DEBUG level (not visible in default INFO output) and moving to the next policy.  
**Root cause**: Boto3 default client has no retry on throttle. The exception was caught generically and treated as a transient per-policy error. It was actually a systemic account-level throttle affecting all subsequent calls.  
**What changed**: Added `Config(retries={"max_attempts": 10, "mode": "adaptive"})` to the boto3 client. Separated `ThrottlingException` from other `ClientError` subtypes — throttle triggers retry with backoff, other ClientErrors (like `NoSuchEntity`) are genuine per-policy failures.  
**Also changed**: Added a `failed_policies` list to the scan summary. If any policy failed to analyze (after retries), it appears in the report as `scan_error` rather than being silently dropped.  
**What this revealed**: Exception handling that catches everything and continues is a detection coverage hole. The correct behavior is: transient errors retry, permanent errors record the failure explicitly, and the summary always shows failures alongside findings.

---

## FAIL-005: Hardcoded API Key in Source Code

**When**: Initial commit review  
**Symptom**: `drift.py` contained `api_key = os.getenv('GEMINI_API_KEY', 'AIzaSy...')` — a real API key as the default fallback.  
**Root cause**: During development, the key was hardcoded for convenience. The `os.getenv` wrapper was added as a "make it configurable" step but the hardcoded default remained.  
**Impact**: The key was visible in every git commit, clone, and fork of the repo. Even if rotated, it exists in git history.  
**What changed**:
- Key removed from code entirely — `os.getenv('GEMINI_API_KEY')` with no default
- If key is not set, tool exits with explicit error pointing to setup instructions
- `.gitignore` updated to exclude `.env` files
- `README.md` credential setup section warns explicitly against hardcoding
**What this revealed**: The `os.getenv('KEY', 'hardcoded_default')` pattern is a security anti-pattern. The hardcoded default defeats the entire purpose of environment-variable credential management. If the environment variable isn't set, the right behavior is to fail fast with a clear error — not silently use the hardcoded value.

---

## FAIL-006: Deny Statements Were Being Flagged as Risky

**When**: Running against production-grade policies  
**Symptom**: An IAM policy with an explicit `Deny` for `Action: *` on sensitive resources was being flagged as CRITICAL — the deny statement contained wildcards, so the wildcard detector triggered on it.  
**Root cause**: Detection logic checked for wildcards in any statement regardless of `Effect`. A `Deny` with `Action: *` is the most restrictive thing you can put in an IAM policy — it was being flagged as the most dangerous.  
**What changed**: All risk analyzers skip statements where `Effect == "Deny"`. Added a specific test case: policy with `Effect: Deny, Action: *, Resource: *` must produce zero findings.  
**What this revealed**: IAM policy evaluation order matters: explicit Deny always overrides Allow. A tool that doesn't understand this basic IAM mechanic produces findings that erode trust — engineers learn to ignore the tool's output because it flags legitimate security controls as risks.

---

## FAIL-007: AI Explanation Blocked the Entire Scan on API Error

**When**: Gemini API rate limit was hit mid-scan  
**Symptom**: Scan processed 15 policies, hit a Gemini rate limit on the 16th, crashed. No findings from policies 1–15 were saved — the scan failed before `save_report()` was called.  
**Root cause**: AI explanation was called synchronously in the main scan loop. Gemini API error propagated up and killed the scan.  
**What changed**: AI explanation now runs in a separate pass after all findings are collected. Finding collection and AI enrichment are decoupled. If Gemini fails on a finding, that finding is saved with `ai_explanation: null` and `ai_explanation_error: "<error>"`. The scan doesn't fail — it degrades gracefully.  
**What this revealed**: External API calls in the hot path of a scan loop are a reliability risk. The finding collection is the critical path. AI enrichment is a nice-to-have. They should fail independently.

---

## Open Issues — Not Yet Fixed

- **Inline policy scanning**: Policies attached directly to users and roles via `put_user_policy` / `put_role_policy` are not customer-managed and won't appear in `list_policies`. These are often the most permissive because they're created ad-hoc. Requires `list_users` → `list_user_policies` → `get_user_policy` chain.
- **Role trust policy analysis**: `AssumeRolePolicyDocument` is separate from the permission policy and is not covered.
- **SCP evaluation**: The effective permission is `IAM policy` ∩ `SCP`. Without SCP context, the tool may flag permissions that are already blocked by an SCP.
