"""
IAM Risk Analyzer Test Suite

All tests run against synthetic policy documents — no AWS credentials needed.
Each test case documents what it's testing and why it was added.

Most tests were added because real policies exposed gaps in detection logic.
See FAILURES.md for the full history of what broke.
"""

import pytest
from analyzer.risk_analyzer import (
    IAMRiskAnalyzer,
    RiskCategory,
    Severity,
)


@pytest.fixture
def analyzer():
    return IAMRiskAnalyzer()


# ---------------------------------------------------------------------------
# CRITICAL: Full admin (Action: * + Resource: *)
# ---------------------------------------------------------------------------

def test_full_admin_wildcard_detected(analyzer):
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    assert result.has_findings
    assert any(f.category == RiskCategory.FULL_ADMIN for f in result.findings)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_full_admin_as_list(analyzer):
    """Action and Resource as lists containing '*' — same as string '*'."""
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Action": ["*"],
            "Resource": ["*"],
        }]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    assert result.has_findings
    assert any(f.category == RiskCategory.FULL_ADMIN for f in result.findings)


# ---------------------------------------------------------------------------
# FAIL-006: Deny statements must NOT be flagged
# ---------------------------------------------------------------------------

def test_deny_with_wildcard_not_flagged(analyzer):
    """
    Deny with Action: * is the most restrictive possible statement.
    FAIL-006: original code flagged this as CRITICAL — wrong.
    """
    doc = {
        "Statement": [{
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
        }]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    assert not result.has_findings, (
        "Deny with Action: * should produce zero findings — it's the most restrictive statement possible. "
        "FAIL-006: wildcard detection must respect Effect."
    )


def test_mixed_allow_deny_only_allow_flagged(analyzer):
    """Allow statement flagged; Deny statement in same policy not flagged."""
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
            {
                "Effect": "Deny",
                "Action": "iam:DeleteUser",
                "Resource": "*",
            },
        ]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    assert result.has_findings
    assert result.max_severity == Severity.CRITICAL
    # Make sure only 1 critical finding (the Allow) not 2
    critical_count = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
    assert critical_count == 1


# ---------------------------------------------------------------------------
# Service-level wildcards
# ---------------------------------------------------------------------------

def test_iam_service_wildcard_flagged_high(analyzer):
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:*",
            "Resource": "*",
        }]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    assert result.has_findings
    assert any(f.category == RiskCategory.SERVICE_WILDCARD for f in result.findings)
    assert any(f.severity == Severity.HIGH for f in result.findings)


def test_s3_service_wildcard_flagged_medium(analyzer):
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*",
        }]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    assert result.has_findings
    assert any(f.category == RiskCategory.SERVICE_WILDCARD for f in result.findings)


def test_specific_actions_not_wildcard_flagged(analyzer):
    """s3:GetObject, s3:PutObject are NOT service wildcards — should not trigger SERVICE_WILDCARD."""
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        }]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    service_wildcard_findings = [f for f in result.findings if f.category == RiskCategory.SERVICE_WILDCARD]
    assert len(service_wildcard_findings) == 0


# ---------------------------------------------------------------------------
# Privilege escalation — cross-statement detection
# ---------------------------------------------------------------------------

def test_passrole_plus_ec2_run_instances_flagged(analyzer):
    """
    iam:PassRole + ec2:RunInstances = privilege escalation path.
    Neither action alone is CRITICAL. The combination is.
    FAIL-002: wildcard-only detection completely missed this.
    """
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": "ec2:RunInstances",
                "Resource": "*",
            },
        ]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    assert result.has_findings
    priv_esc = [f for f in result.findings if f.category == RiskCategory.PRIVILEGE_ESCALATION]
    assert len(priv_esc) > 0, (
        "iam:PassRole + ec2:RunInstances is a known privilege escalation path. "
        "This allows attaching an admin role to an EC2 instance without needing Action: *."
    )
    assert priv_esc[0].severity == Severity.CRITICAL


def test_passrole_plus_lambda_flagged(analyzer):
    """iam:PassRole + lambda:CreateFunction = another escalation path."""
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
            "Resource": "*",
        }]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    priv_esc = [f for f in result.findings if f.category == RiskCategory.PRIVILEGE_ESCALATION]
    assert len(priv_esc) > 0


def test_passrole_alone_not_priv_esc(analyzer):
    """iam:PassRole alone, without compute launch capability, is not a complete escalation path."""
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "arn:aws:iam::123456789012:role/specific-role",
        }]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    priv_esc = [f for f in result.findings if f.category == RiskCategory.PRIVILEGE_ESCALATION]
    assert len(priv_esc) == 0, (
        "iam:PassRole scoped to a specific role ARN, without any compute launch action, "
        "is not a complete privilege escalation path."
    )


# ---------------------------------------------------------------------------
# Logging suppression
# ---------------------------------------------------------------------------

def test_cloudtrail_stop_logging_flagged(analyzer):
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "cloudtrail:StopLogging",
            "Resource": "*",
        }]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    assert result.has_findings
    assert any(f.category == RiskCategory.LOGGING_SUPPRESSION for f in result.findings)


def test_guardduty_delete_detector_flagged(analyzer):
    """GuardDuty deletion should be caught — attacker covers tracks by disabling detection."""
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Action": ["guardduty:DeleteDetector", "guardduty:DisassociateFromMasterAccount"],
            "Resource": "*",
        }]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    assert result.has_findings
    assert any(f.category == RiskCategory.LOGGING_SUPPRESSION for f in result.findings)


# ---------------------------------------------------------------------------
# Missing MFA condition
# ---------------------------------------------------------------------------

def test_iam_delete_user_without_mfa_flagged(analyzer):
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:DeleteUser",
            "Resource": "*",
        }]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    assert result.has_findings
    assert any(f.category == RiskCategory.MISSING_MFA_CONDITION for f in result.findings)


def test_iam_delete_user_with_mfa_not_flagged(analyzer):
    """iam:DeleteUser with MFA condition — acceptable pattern."""
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:DeleteUser",
            "Resource": "*",
            "Condition": {
                "Bool": {"aws:MultiFactorAuthPresent": "true"}
            }
        }]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    mfa_findings = [f for f in result.findings if f.category == RiskCategory.MISSING_MFA_CONDITION]
    assert len(mfa_findings) == 0


# ---------------------------------------------------------------------------
# Unrestricted STS
# ---------------------------------------------------------------------------

def test_sts_assume_role_wildcard_resource_flagged(analyzer):
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "*",
        }]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    assert result.has_findings
    assert any(f.category == RiskCategory.UNRESTRICTED_STS for f in result.findings)


def test_sts_assume_role_specific_resource_not_flagged(analyzer):
    """sts:AssumeRole scoped to a specific role ARN — least privilege, not a finding."""
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::123456789012:role/specific-role",
        }]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    sts_findings = [f for f in result.findings if f.category == RiskCategory.UNRESTRICTED_STS]
    assert len(sts_findings) == 0


# ---------------------------------------------------------------------------
# Clean policies produce no findings
# ---------------------------------------------------------------------------

def test_least_privilege_policy_no_findings(analyzer):
    """
    A properly scoped, least-privilege policy should produce zero findings.
    If this test fails, the detector has a false positive that needs investigation.
    """
    doc = {
        "Statement": [
            {
                "Sid": "S3ReadSpecificBucket",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    "arn:aws:s3:::my-app-bucket",
                    "arn:aws:s3:::my-app-bucket/*",
                ],
            },
            {
                "Sid": "CloudWatchLogsWrite",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/my-app/*",
            },
        ]
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    assert not result.has_findings, (
        f"Least-privilege policy incorrectly flagged with {len(result.findings)} findings: "
        f"{[f.category.value for f in result.findings]}"
    )


def test_single_statement_not_list(analyzer):
    """IAM allows a single Statement object instead of a list. Both forms must work."""
    doc = {
        "Statement": {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
    }
    result = analyzer.analyze("TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy", doc)
    assert result.has_findings
    assert any(f.category == RiskCategory.FULL_ADMIN for f in result.findings)


# ---------------------------------------------------------------------------
# Real-world policy sample from the original lab (ReadOnlyS3CloudWatchPolicy)
# ---------------------------------------------------------------------------

def test_original_lab_sample_policy(analyzer):
    """
    The policy from the original lab document:
    s3:Get*, s3:List*, cloudwatch:Get*, cloudwatch:List* with Resource: *

    Old tool flagged this only because Resource: * was present.
    Multi-signal analysis also flags RESOURCE_WILDCARD on the write-capable
    actions if any exist, and identifies the specific data exposure.
    """
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:Get*",
                "s3:List*",
                "cloudwatch:Get*",
                "cloudwatch:List*",
            ],
            "Resource": "*",
        }]
    }
    result = analyzer.analyze(
        "ReadOnlyS3CloudWatchPolicy",
        "arn:aws:iam::816069160759:policy/ReadOnlyS3CloudWatchPolicy",
        doc,
    )
    # s3:Get* with Resource: * should be flagged as broad S3 read
    assert result.has_findings
    s3_read_findings = [f for f in result.findings if f.category == RiskCategory.BROAD_S3_READ]
    assert len(s3_read_findings) > 0, (
        "s3:Get* with Resource: * should be flagged as broad S3 read — "
        "grants read access to every object in every bucket."
    )
