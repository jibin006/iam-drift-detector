"""
IAM Risk Analyzer

Multi-signal risk detection for IAM policy documents. Eight risk categories,
severity scoring, privilege escalation path detection.

This is NOT wildcard detection. Wildcard detection catches ~30% of the
dangerous IAM configurations in the wild. The rest are combinations:
  - iam:PassRole + ec2:RunInstances = admin escalation without Action: *
  - cloudtrail:StopLogging = cover your tracks
  - Missing MFA conditions on delete operations

Detection runs on the policy document (dict) returned from
iam:GetPolicyVersion. No network calls — pure static analysis.

See DECISIONS.md ADR-002 for the reasoning on multi-signal vs wildcard-only.
See FAILURES.md FAIL-002 for what wildcard-only missed in practice.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RiskCategory(str, Enum):
    FULL_ADMIN = "full_admin_wildcard"
    SERVICE_WILDCARD = "service_level_wildcard"
    PRIVILEGE_ESCALATION = "privilege_escalation_path"
    LOGGING_SUPPRESSION = "logging_suppression"
    MISSING_MFA_CONDITION = "missing_mfa_condition"
    UNRESTRICTED_STS = "unrestricted_sts_assume"
    BROAD_S3_READ = "broad_s3_read"
    RESOURCE_WILDCARD = "resource_wildcard_only"


@dataclass
class RiskFinding:
    """A single risk finding for one statement in a policy."""
    category: RiskCategory
    severity: Severity
    statement: dict
    detail: str
    remediation: str

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "statement": self.statement,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class PolicyAnalysisResult:
    """Aggregated findings for one IAM policy."""
    policy_name: str
    policy_arn: str
    findings: list[RiskFinding] = field(default_factory=list)
    scan_error: str | None = None
    ai_explanation: str | None = None
    ai_explanation_error: str | None = None

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for s in order:
            if any(f.severity == s for f in self.findings):
                return s
        return None

    def to_dict(self) -> dict:
        return {
            "policy_name": self.policy_name,
            "policy_arn": self.policy_arn,
            "max_severity": self.max_severity.value if self.max_severity else None,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "ai_explanation": self.ai_explanation,
            "ai_explanation_error": self.ai_explanation_error,
            "scan_error": self.scan_error,
        }


# ---------------------------------------------------------------------------
# Privilege escalation action sets
# These combinations allow admin access escalation without Action: *
# Reference: AWS IAM privilege escalation research (Rhino Security Labs)
# ---------------------------------------------------------------------------

# If a policy grants iam:PassRole AND any of these, the principal can
# attach an admin role to a compute resource they control
_PASSROLE_ESCALATION_PARTNERS: frozenset[str] = frozenset([
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "glue:CreateJob",
    "glue:UpdateJob",
    "datapipeline:CreatePipeline",
    "datapipeline:PutPipelineDefinition",
    "cloudformation:CreateStack",
    "cloudformation:UpdateStack",
    "ecs:RegisterTaskDefinition",
    "ecs:RunTask",
    "sagemaker:CreateTrainingJob",
    "sagemaker:CreateProcessingJob",
])

# Actions that allow creating or modifying IAM resources directly
_IAM_CREATE_MODIFY_ACTIONS: frozenset[str] = frozenset([
    "iam:CreateRole",
    "iam:CreateUser",
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
])

# Actions that suppress audit trails — attacker's cover
_LOGGING_SUPPRESSION_ACTIONS: frozenset[str] = frozenset([
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "cloudtrail:UpdateTrail",
    "cloudtrail:PutEventSelectors",
    "cloudwatch:DeleteAlarms",
    "cloudwatch:DisableAlarmActions",
    "logs:DeleteLogGroup",
    "logs:DeleteLogStream",
    "config:DeleteConfigurationRecorder",
    "config:StopConfigurationRecorder",
    "guardduty:DeleteDetector",
    "guardduty:DisassociateFromMasterAccount",
    "securityhub:DisableSecurityHub",
])

# Sensitive IAM delete operations that should require MFA
_MFA_REQUIRED_ACTIONS: frozenset[str] = frozenset([
    "iam:DeleteUser",
    "iam:DeleteRole",
    "iam:DeletePolicy",
    "iam:DeleteAccessKey",
    "iam:DeactivateMFADevice",
    "iam:DeleteVirtualMFADevice",
])


class IAMRiskAnalyzer:
    """
    Static analyzer for IAM policy documents.

    Usage:
        analyzer = IAMRiskAnalyzer()
        result = analyzer.analyze(policy_name, policy_arn, policy_document)

    Input: the decoded policy document dict from iam:GetPolicyVersion.
    No network calls made here — pure document analysis.
    """

    def analyze(
        self,
        policy_name: str,
        policy_arn: str,
        document: dict[str, Any],
    ) -> PolicyAnalysisResult:
        result = PolicyAnalysisResult(policy_name=policy_name, policy_arn=policy_arn)

        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]  # single-statement policies

        # Collect all Allow actions and resources across statements for
        # cross-statement escalation path detection
        all_allow_actions: list[str] = []
        all_allow_resources: list[str] = []

        for stmt in statements:
            # FAIL-006: Deny statements are not risks — they're restrictions.
            # Wildcard in a Deny is the most restrictive thing possible.
            if stmt.get("Effect", "Allow").upper() == "DENY":
                continue

            actions = self._normalize_list(stmt.get("Action", []))
            resources = self._normalize_list(stmt.get("Resource", []))
            conditions = stmt.get("Condition", {})

            all_allow_actions.extend(actions)
            all_allow_resources.extend(resources)

            # Per-statement checks
            result.findings.extend(self._check_full_admin(stmt, actions, resources))
            result.findings.extend(self._check_service_wildcard(stmt, actions))
            result.findings.extend(self._check_logging_suppression(stmt, actions))
            result.findings.extend(self._check_missing_mfa(stmt, actions, conditions))
            result.findings.extend(self._check_unrestricted_sts(stmt, actions, resources, conditions))
            result.findings.extend(self._check_broad_s3_read(stmt, actions, resources, conditions))
            result.findings.extend(self._check_resource_wildcard(stmt, actions, resources))

        # Cross-statement privilege escalation check
        result.findings.extend(
            self._check_privilege_escalation(statements, all_allow_actions)
        )

        return result

    # -----------------------------------------------------------------------
    # Individual risk checks
    # -----------------------------------------------------------------------

    @staticmethod
    def _check_full_admin(
        stmt: dict, actions: list[str], resources: list[str]
    ) -> list[RiskFinding]:
        """Action: * + Resource: * = full admin. Highest severity."""
        if "*" in actions and "*" in resources:
            return [RiskFinding(
                category=RiskCategory.FULL_ADMIN,
                severity=Severity.CRITICAL,
                statement=stmt,
                detail=(
                    "Policy grants unrestricted access to all AWS actions on all resources. "
                    "Equivalent to root access within the permission boundary."
                ),
                remediation=(
                    "Replace with least-privilege permissions scoped to specific services and resources. "
                    "If admin access is required, use a tightly scoped role with MFA enforcement "
                    "and time-limited sessions rather than a standing policy."
                ),
            )]
        return []

    @staticmethod
    def _check_service_wildcard(stmt: dict, actions: list[str]) -> list[RiskFinding]:
        """
        Service-level wildcard: iam:*, s3:*, ec2:*.
        Grants all actions for a service — not as broad as Action: * but still dangerous
        for high-privilege services.
        """
        high_risk_services = {"iam", "sts", "organizations", "kms"}
        medium_risk_services = {"s3", "ec2", "rds", "lambda", "secretsmanager", "ssm"}

        findings = []
        for action in actions:
            if not action.endswith(":*"):
                continue
            service = action.split(":")[0].lower()
            if service in high_risk_services:
                findings.append(RiskFinding(
                    category=RiskCategory.SERVICE_WILDCARD,
                    severity=Severity.HIGH,
                    statement=stmt,
                    detail=(
                        f"Policy grants all {service.upper()} actions ({service}:*). "
                        f"{'IAM wildcard allows creating users, roles, policies — full control plane access.' if service == 'iam' else ''}"
                        f"{'STS wildcard allows assuming any role in or across the account.' if service == 'sts' else ''}"
                        f"{'Organizations wildcard can modify SCPs affecting the entire organization.' if service == 'organizations' else ''}"
                        f"{'KMS wildcard allows key deletion and disabling, potentially destroying encrypted data access.' if service == 'kms' else ''}"
                    ),
                    remediation=f"Replace {action} with specific {service} actions required for the use case.",
                ))
            elif service in medium_risk_services:
                findings.append(RiskFinding(
                    category=RiskCategory.SERVICE_WILDCARD,
                    severity=Severity.MEDIUM,
                    statement=stmt,
                    detail=f"Policy grants all {service.upper()} actions ({service}:*). Scope to specific operations.",
                    remediation=f"Replace {action} with specific {service} actions and resource ARNs.",
                ))
        return findings

    @staticmethod
    def _check_logging_suppression(stmt: dict, actions: list[str]) -> list[RiskFinding]:
        """
        Actions that disable audit trails — attacker's first move to cover tracks.
        Not an "overly broad" permission issue — a targeted dangerous capability.
        Wildcard-only detection misses this entirely.
        """
        matched = [a for a in actions if a in _LOGGING_SUPPRESSION_ACTIONS]
        if not matched:
            return []
        return [RiskFinding(
            category=RiskCategory.LOGGING_SUPPRESSION,
            severity=Severity.HIGH,
            statement=stmt,
            detail=(
                f"Policy grants logging/monitoring suppression actions: {matched}. "
                "An attacker with these permissions can disable CloudTrail, GuardDuty, "
                "or Config before performing malicious actions, eliminating the audit trail."
            ),
            remediation=(
                "Remove logging suppression actions unless this is an explicit security operations role. "
                "If required, add a Condition requiring MFA and restrict to specific trail/detector ARNs."
            ),
        )]

    @staticmethod
    def _check_missing_mfa(
        stmt: dict, actions: list[str], conditions: dict
    ) -> list[RiskFinding]:
        """
        Sensitive delete/deactivation operations without MFA condition.
        Deleting an IAM user, deactivating MFA — these should require MFA on the caller.
        """
        matched = [a for a in actions if a in _MFA_REQUIRED_ACTIONS]
        if not matched:
            return []

        # Check for MFA condition presence
        has_mfa_condition = (
            "aws:MultiFactorAuthPresent" in str(conditions)
            or "aws:MultiFactorAuthAge" in str(conditions)
        )
        if has_mfa_condition:
            return []

        return [RiskFinding(
            category=RiskCategory.MISSING_MFA_CONDITION,
            severity=Severity.HIGH,
            statement=stmt,
            detail=(
                f"Policy grants sensitive operations {matched} without requiring MFA. "
                "These operations can permanently destroy access controls — "
                "an attacker with temporary credential access (e.g., leaked access key) "
                "can perform them without a second factor."
            ),
            remediation=(
                'Add condition: {"Bool": {"aws:MultiFactorAuthPresent": "true"}} '
                "to enforce MFA on these operations."
            ),
        )]

    @staticmethod
    def _check_unrestricted_sts(
        stmt: dict, actions: list[str], resources: list[str], conditions: dict
    ) -> list[RiskFinding]:
        """
        sts:AssumeRole with Resource: * and no condition = can assume any role in the account.
        Lateral movement and privilege escalation without touching IAM directly.
        """
        sts_actions = [a for a in actions if a in ("sts:AssumeRole", "sts:*")]
        if not sts_actions:
            return []
        if "*" not in resources:
            return []  # scoped to specific roles — acceptable
        if conditions:
            return []  # conditions limit blast radius — flagging would be noisy

        return [RiskFinding(
            category=RiskCategory.UNRESTRICTED_STS,
            severity=Severity.HIGH,
            statement=stmt,
            detail=(
                "Policy allows assuming any role in the account (sts:AssumeRole, Resource: *) "
                "without condition constraints. This allows lateral movement to any role "
                "the account owns, including admin roles."
            ),
            remediation=(
                "Scope Resource to specific role ARNs: "
                '"arn:aws:iam::ACCOUNT_ID:role/specific-role". '
                "If cross-account assume is required, add ExternalId condition."
            ),
        )]

    @staticmethod
    def _check_broad_s3_read(
        stmt: dict, actions: list[str], resources: list[str], conditions: dict
    ) -> list[RiskFinding]:
        """
        s3:GetObject with Resource: * = read every object in every bucket in the account.
        Common data exfiltration path.
        """
        s3_read_actions = [a for a in actions if a in ("s3:GetObject", "s3:*", "s3:Get*")]
        if not s3_read_actions:
            return []
        if "*" not in resources:
            return []
        if conditions:
            return []

        return [RiskFinding(
            category=RiskCategory.BROAD_S3_READ,
            severity=Severity.MEDIUM,
            statement=stmt,
            detail=(
                f"Policy grants {s3_read_actions} with Resource: * — read access to "
                "every object in every S3 bucket in the account. "
                "A compromised principal with this policy can exfiltrate all S3 data."
            ),
            remediation=(
                "Scope Resource to specific bucket ARNs: "
                '"arn:aws:s3:::bucket-name/*". '
                "If cross-bucket access is required, enumerate the specific buckets."
            ),
        )]

    @staticmethod
    def _check_resource_wildcard(
        stmt: dict, actions: list[str], resources: list[str]
    ) -> list[RiskFinding]:
        """
        Non-wildcard actions with Resource: * — less severe than service wildcard
        but still worth flagging when actions are not inherently requiring wildcard.
        """
        if "*" not in resources:
            return []
        # Already caught by higher-severity checks
        if "*" in actions or any(a.endswith(":*") for a in actions):
            return []
        # Skip actions that legitimately require Resource: * (list operations, etc.)
        list_actions = [a for a in actions if a.startswith(("List", "Describe", "Get"))]
        non_list = [a for a in actions if a not in list_actions]
        if not non_list:
            return []  # all actions are read/list — Resource: * is less concerning

        return [RiskFinding(
            category=RiskCategory.RESOURCE_WILDCARD,
            severity=Severity.LOW,
            statement=stmt,
            detail=(
                f"Policy grants {non_list} on Resource: *. "
                "Consider scoping to specific resource ARNs to follow least privilege."
            ),
            remediation="Replace Resource: * with specific ARNs for each action's target resources.",
        )]

    def _check_privilege_escalation(
        self, statements: list[dict], all_allow_actions: list[str]
    ) -> list[RiskFinding]:
        """
        Cross-statement privilege escalation path detection.

        iam:PassRole alone is not dangerous. ec2:RunInstances alone is not dangerous.
        Together, they allow attaching an admin role to an EC2 instance the attacker controls.
        This check requires looking across all Allow statements, not just individual ones.

        Reference: Rhino Security Labs privilege escalation research (2018), AWS re:Inforce 2022
        """
        findings = []
        action_set = set(all_allow_actions)

        has_pass_role = "iam:PassRole" in action_set or "iam:*" in action_set
        if not has_pass_role:
            return []

        # Check for PassRole + compute launch = privilege escalation
        compute_escalation = action_set & _PASSROLE_ESCALATION_PARTNERS
        if compute_escalation:
            findings.append(RiskFinding(
                category=RiskCategory.PRIVILEGE_ESCALATION,
                severity=Severity.CRITICAL,
                statement={"_cross_statement_finding": True, "actions": list(action_set)},
                detail=(
                    f"Policy grants iam:PassRole AND {sorted(compute_escalation)}. "
                    "This is a privilege escalation path: a principal with PassRole can attach "
                    "an admin IAM role to a compute resource they launch, granting themselves "
                    "admin-level access without ever having Action: *. "
                    "This is one of the most common escalation paths in misconfigured AWS accounts."
                ),
                remediation=(
                    "If PassRole is required, constrain it with a Condition on iam:PassedToService "
                    "and a resource condition scoping it to specific role ARNs — not Resource: *. "
                    "Example: add condition {\"StringEquals\": {\"iam:PassedToService\": \"ec2.amazonaws.com\"}} "
                    "and restrict Resource to the specific role ARN."
                ),
            ))

        # Check for direct IAM create/modify = direct escalation
        direct_iam_escalation = action_set & _IAM_CREATE_MODIFY_ACTIONS
        if "iam:PassRole" in action_set and direct_iam_escalation:
            findings.append(RiskFinding(
                category=RiskCategory.PRIVILEGE_ESCALATION,
                severity=Severity.CRITICAL,
                statement={"_cross_statement_finding": True, "actions": list(action_set)},
                detail=(
                    f"Policy grants iam:PassRole AND IAM modify actions {sorted(direct_iam_escalation)}. "
                    "This allows creating a new IAM role with admin permissions and passing it to compute, "
                    "or directly attaching admin policies to existing principals."
                ),
                remediation=(
                    "IAM write actions should only exist in dedicated IAM administration roles "
                    "with MFA enforcement, IP restrictions, and break-glass access controls. "
                    "Not in service roles used by applications."
                ),
            ))

        return findings

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _normalize_list(value: Any) -> list[str]:
        """Normalize Action/Resource to a list. IAM allows string or list."""
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return value
        return []
