"""
Drift Comparator Test Suite

Tests the comparison logic between live IAM state and stored baselines.
No AWS credentials needed — pure structural comparison.
"""

import pytest
from drift_comparator import DriftType, IAMDriftComparator


@pytest.fixture
def comparator():
    return IAMDriftComparator()


# Base policy for most tests
BASE_POLICY_DOC = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "S3ReadAccess",
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:ListBucket"],
        "Resource": "arn:aws:s3:::my-bucket/*",
    }]
}

SAMPLE_ARN = "arn:aws:iam::123456789012:policy/MyPolicy"


def make_baseline(policies: list[dict]) -> dict:
    """Helper to construct a baseline dict from policy entries."""
    return {
        "generated_at": "2025-01-01T00:00:00+00:00",
        "policies": {
            p["arn"]: {
                "policy_name": p["policy_name"],
                "document": p["document"],
            }
            for p in policies
        },
    }


def test_no_drift_when_identical(comparator):
    """Identical live and baseline = no findings."""
    baseline = make_baseline([{
        "arn": SAMPLE_ARN,
        "policy_name": "MyPolicy",
        "document": BASE_POLICY_DOC,
    }])
    live = [{"arn": SAMPLE_ARN, "policy_name": "MyPolicy", "document": BASE_POLICY_DOC}]

    findings = comparator.compare_all(live, baseline)
    assert len(findings) == 0


def test_policy_added_in_live(comparator):
    """Policy in live but not in baseline = POLICY_ADDED (unmanaged, out of IaC)."""
    baseline = make_baseline([])  # empty baseline
    live = [{"arn": SAMPLE_ARN, "policy_name": "MyPolicy", "document": BASE_POLICY_DOC}]

    findings = comparator.compare_all(live, baseline)
    assert len(findings) == 1
    assert findings[0].drift_type == DriftType.POLICY_ADDED
    assert findings[0].policy_name == "MyPolicy"


def test_policy_removed_from_live(comparator):
    """Policy in baseline but gone from live = POLICY_REMOVED."""
    baseline = make_baseline([{
        "arn": SAMPLE_ARN,
        "policy_name": "MyPolicy",
        "document": BASE_POLICY_DOC,
    }])
    live = []  # policy deleted from AWS

    findings = comparator.compare_all(live, baseline)
    assert len(findings) == 1
    assert findings[0].drift_type == DriftType.POLICY_REMOVED


def test_permissions_expanded_new_action(comparator):
    """Live policy has more actions than baseline = PERMISSIONS_EXPANDED."""
    baseline = make_baseline([{
        "arn": SAMPLE_ARN,
        "policy_name": "MyPolicy",
        "document": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "S3ReadAccess",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::my-bucket/*",
            }]
        },
    }])
    live_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "S3ReadAccess",
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:DeleteObject"],  # DeleteObject added
            "Resource": "arn:aws:s3:::my-bucket/*",
        }]
    }
    live = [{"arn": SAMPLE_ARN, "policy_name": "MyPolicy", "document": live_doc}]

    findings = comparator.compare_all(live, baseline)
    expanded = [f for f in findings if f.drift_type == DriftType.PERMISSIONS_EXPANDED]
    assert len(expanded) == 1
    assert "s3:DeleteObject" in expanded[0].detail


def test_condition_removed_flagged(comparator):
    """
    Condition removed from live — most dangerous drift type.
    Removing aws:MultiFactorAuthPresent eliminates MFA enforcement
    without changing the action list.
    """
    baseline = make_baseline([{
        "arn": SAMPLE_ARN,
        "policy_name": "MyPolicy",
        "document": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DeleteWithMFA",
                "Effect": "Allow",
                "Action": "iam:DeleteUser",
                "Resource": "*",
                "Condition": {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"}
                }
            }]
        },
    }])
    live_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DeleteWithMFA",
            "Effect": "Allow",
            "Action": "iam:DeleteUser",
            "Resource": "*",
            # Condition removed — MFA no longer enforced
        }]
    }
    live = [{"arn": SAMPLE_ARN, "policy_name": "MyPolicy", "document": live_doc}]

    findings = comparator.compare_all(live, baseline)
    condition_findings = [f for f in findings if f.drift_type == DriftType.CONDITION_REMOVED]
    assert len(condition_findings) == 1, (
        "Removing MFA condition from a policy should be flagged as CONDITION_REMOVED. "
        "The action list didn't change but the security constraint was dropped."
    )


def test_permissions_reduced_tracked(comparator):
    """Live policy is more restrictive than baseline — tracked, lower urgency."""
    baseline = make_baseline([{
        "arn": SAMPLE_ARN,
        "policy_name": "MyPolicy",
        "document": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "S3Access",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                "Resource": "arn:aws:s3:::my-bucket/*",
            }]
        },
    }])
    live_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "S3Access",
            "Effect": "Allow",
            "Action": ["s3:GetObject"],  # PutObject and DeleteObject removed
            "Resource": "arn:aws:s3:::my-bucket/*",
        }]
    }
    live = [{"arn": SAMPLE_ARN, "policy_name": "MyPolicy", "document": live_doc}]

    findings = comparator.compare_all(live, baseline)
    reduced = [f for f in findings if f.drift_type == DriftType.PERMISSIONS_REDUCED]
    assert len(reduced) == 1


def test_generate_baseline_structure(comparator):
    """Baseline generation produces correct structure."""
    live_policies = [
        {
            "arn": SAMPLE_ARN,
            "policy_name": "MyPolicy",
            "document": BASE_POLICY_DOC,
        }
    ]
    baseline = comparator.generate_baseline(live_policies)

    assert "generated_at" in baseline
    assert "policy_count" in baseline
    assert baseline["policy_count"] == 1
    assert SAMPLE_ARN in baseline["policies"]
    assert baseline["policies"][SAMPLE_ARN]["policy_name"] == "MyPolicy"


def test_removed_statement_is_reported_as_permission_reduction(comparator):
    """Removing a Sid-bearing statement must not disappear from drift results."""
    baseline = make_baseline([{
        "arn": SAMPLE_ARN,
        "policy_name": "MyPolicy",
        "document": BASE_POLICY_DOC,
    }])
    live = [{
        "arn": SAMPLE_ARN,
        "policy_name": "MyPolicy",
        "document": {"Version": "2012-10-17", "Statement": []},
    }]

    findings = comparator.compare_all(live, baseline)
    assert any(f.drift_type == DriftType.PERMISSIONS_REDUCED for f in findings)
    assert any("S3ReadAccess" in f.detail for f in findings)


def test_explicit_deny_changed_to_allow_is_reported_as_expansion(comparator):
    """An Effect flip from Deny to Allow is security-significant even with same actions."""
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "ProtectAdmin",
            "Effect": "Deny",
            "Action": "iam:CreateAccessKey",
            "Resource": "*",
        }],
    }
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "ProtectAdmin",
            "Effect": "Allow",
            "Action": "iam:CreateAccessKey",
            "Resource": "*",
        }],
    }
    baseline = make_baseline([{
        "arn": SAMPLE_ARN,
        "policy_name": "MyPolicy",
        "document": deny_policy,
    }])
    live = [{
        "arn": SAMPLE_ARN,
        "policy_name": "MyPolicy",
        "document": allow_policy,
    }]

    findings = comparator.compare_all(live, baseline)
    assert any(f.drift_type == DriftType.PERMISSIONS_EXPANDED for f in findings)
    assert any("Effect from Deny to Allow" in f.detail for f in findings)


def test_nested_condition_key_removal_is_reported(comparator):
    """Removing a condition key inside an existing operator is still drift."""
    baseline_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DeleteWithMFAAndSourceIp",
            "Effect": "Allow",
            "Action": "iam:DeleteUser",
            "Resource": "*",
            "Condition": {
                "Bool": {"aws:MultiFactorAuthPresent": "true"},
                "IpAddress": {"aws:SourceIp": "192.0.2.0/24"},
            },
        }],
    }
    live_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DeleteWithMFAAndSourceIp",
            "Effect": "Allow",
            "Action": "iam:DeleteUser",
            "Resource": "*",
            "Condition": {
                "Bool": {"aws:MultiFactorAuthPresent": "true"},
            },
        }],
    }
    baseline = make_baseline([{
        "arn": SAMPLE_ARN,
        "policy_name": "MyPolicy",
        "document": baseline_policy,
    }])
    live = [{
        "arn": SAMPLE_ARN,
        "policy_name": "MyPolicy",
        "document": live_policy,
    }]

    findings = comparator.compare_all(live, baseline)
    condition_findings = [
        f for f in findings if f.drift_type == DriftType.CONDITION_REMOVED
    ]
    assert len(condition_findings) == 1
    assert "IpAddress.aws:SourceIp" in condition_findings[0].detail
