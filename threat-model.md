# Threat Model — IAM Drift Detector

## What We're Protecting Against

This tool detects two attack enablers in IAM configuration:

1. **Misconfigured permissions** — policies that grant more access than intended, creating attack surface
2. **Configuration drift** — policies that have changed from the IaC-declared state, indicating unreviewed changes

It does not prevent attacks directly. It surfaces the conditions that make attacks easier.

---

## Threat Scenarios This Tool Detects

### T1: Privilege Escalation via PassRole + Compute

An engineer creates a service role for a data pipeline. They grant `iam:PassRole` (needed to attach a role to an EC2 instance) and `ec2:RunInstances` (needed to launch instances). Neither action looks alarming in isolation. Together, an attacker with access to the credentials of a principal with this policy can launch an EC2 instance, attach an admin role to it, and execute commands on that instance — gaining admin access without ever touching `Action: *`.

**Detection**: `PRIVILEGE_ESCALATION` finding in risk analysis.  
**Why wildcard-only detection misses it**: Neither action contains `*`. The policy looks compliant by naive inspection.

### T2: Manual Console Changes Escaping IaC

A developer needs temporary access to debug a production issue. They modify an IAM policy in the console to add `s3:GetObject` on all buckets. The debug session ends, the console change is forgotten. The policy now has broader permissions than Terraform declares — permanently, unreviewed, outside version control.

**Detection**: `PERMISSIONS_EXPANDED` drift finding comparing live state against baseline.  
**Why risk-only scanning misses it**: The expanded policy might not be obviously risky — it depends on whether the change was appropriate. The question isn't just "is this risky" but "was this authorized."

### T3: Audit Trail Suppression Pre-Attack

An attacker with compromised credentials that include `cloudtrail:StopLogging` stops the CloudTrail trail before performing exfiltration, then restarts it. The exfiltration activity appears in no logs.

**Detection**: `LOGGING_SUPPRESSION` finding. The capability exists in a policy — if a principal can stop logging, that's a finding regardless of whether they've used it.  
**Why wildcard-only misses it**: `cloudtrail:StopLogging` is a specific action, not a wildcard.

### T4: MFA Bypass for Sensitive Operations

A policy grants `iam:DeleteUser` without an MFA condition. An attacker with a leaked long-lived access key (no MFA involved) can delete IAM users. With an MFA condition, the leaked access key alone is insufficient — the attacker also needs the MFA device.

**Detection**: `MISSING_MFA_CONDITION` finding on sensitive IAM operations.

### T5: Unmanaged Policy Outside IaC

A policy is created manually — perhaps during an incident response, perhaps by a contractor who was given temporary access. It's never added to Terraform. It persists after the need is gone. If it's overly permissive, it's a standing attack surface that no IaC review would ever catch because it's not in IaC.

**Detection**: `POLICY_ADDED` drift finding — policy in live AWS but not in baseline.

---

## What This Tool Is NOT Detecting

| Gap | Explanation |
|---|---|
| Inline policies | Not customer-managed, not returned by `list_policies`. Requires separate enumeration. |
| Role trust policies | Who can assume a role is a separate document from permission policies. |
| Resource-based policies | S3 bucket policies, KMS key policies, Lambda resource policies — separate API calls per service. |
| SCPs (Service Control Policies) | Org-level controls can restrict effective permissions below what the IAM policy grants. |
| Effective permissions | This tool analyzes policy documents, not effective permissions (IAM policy evaluation requires considering all attached policies, permission boundaries, and SCPs simultaneously). |
| Credential exposure | Leaked access keys, public EC2 instance profiles — IAM configuration, not credential handling. |

A complete IAM security posture requires all of the above. This tool is one component.

---

## Data Flow and Trust Boundaries

```
AWS Account
    │  (API call — authenticated, encrypted, within AWS)
    │
AWS IAM API
    │  (policy documents fetched)
    │
IAM Drift Detector (this process)
    │  • ARNs stripped of account IDs before external calls
    │  • Policy documents stay in process memory
    │
    ├── Risk Analysis (no external calls)
    │
    └── Gemini API (external, encrypted)
           • Receives: policy document structure (actions, resources, conditions)
           • Does NOT receive: account IDs, specific resource ARNs with account context
           • See DECISIONS.md ADR-003 for full privacy reasoning
```

**Trust boundary**: IAM policy document content (action names, condition keys, resource patterns) crosses the AWS account boundary to reach Gemini. Account IDs are stripped. Whether this is acceptable depends on the organization's data classification for IAM configuration metadata.

If IAM configuration is classified as confidential: deploy the Bedrock-based explainer alternative (not yet implemented — see open issues in FAILURES.md).
