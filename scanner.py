"""
AWS IAM Policy Scanner

Enumerates customer-managed IAM policies with:
  - Full pagination (handles 500+ policy accounts)
  - Adaptive retry with exponential backoff on throttle
  - Per-policy error tracking (no silent drops)
  - Scan metadata for operational visibility

See FAILURES.md FAIL-003 (missing pagination) and FAIL-004 (silent throttle drops)
for the history of why these are explicitly built.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Generator

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


@dataclass
class ScanSummary:
    total_found: int = 0
    total_scanned: int = 0
    total_failed: int = 0
    failed_policies: list[dict] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    @property
    def coverage_pct(self) -> float:
        if self.total_found == 0:
            return 0.0
        return (self.total_scanned / self.total_found) * 100

    def to_dict(self) -> dict:
        return {
            "total_found": self.total_found,
            "total_scanned": self.total_scanned,
            "total_failed": self.total_failed,
            "coverage_pct": round(self.coverage_pct, 1),
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
            "failed_policies": self.failed_policies,
        }


class IAMScanner:
    """
    Scans customer-managed IAM policies in an AWS account.

    Returns policy documents ready for risk analysis and drift comparison.

    Fail behavior:
      - Throttle: retry with adaptive backoff (up to 10 attempts)
      - NoSuchEntity / AccessDenied per-policy: record in failed_policies, continue
      - ListPolicies failure: propagate — scanner cannot proceed without the list
    """

    def __init__(self, region: str = "us-east-1"):
        # Adaptive retry mode: uses AWS token bucket algorithm vs fixed backoff.
        # Backs off when throttled, accelerates when capacity is available.
        # See DECISIONS.md ADR-005.
        self._iam = boto3.client(
            "iam",
            region_name=region,
            config=Config(
                retries={"max_attempts": 10, "mode": "adaptive"}
            ),
        )

    def scan(self) -> tuple[list[dict[str, Any]], ScanSummary]:
        """
        Enumerate all customer-managed policies and fetch their active documents.

        Returns:
            (list of policy dicts, ScanSummary)

        Each policy dict:
        {
            "policy_name": str,
            "arn": str,
            "document": dict,  # the actual IAM policy document
            "attachment_count": int,
            "created_date": str,
            "updated_date": str,
        }

        FAIL-003: pagination is not optional. Without it, accounts with >100
        customer-managed policies are silently truncated.
        """
        summary = ScanSummary()
        policies: list[dict[str, Any]] = []
        start = time.monotonic()

        logger.info("Starting IAM policy scan (customer-managed only)...")

        for policy_meta in self._list_all_policies():
            summary.total_found += 1
            arn = policy_meta["Arn"]
            policy_name = policy_meta["PolicyName"]

            try:
                document = self._get_policy_document(arn, policy_meta["DefaultVersionId"])
                policies.append({
                    "policy_name": policy_name,
                    "arn": arn,
                    "document": document,
                    "attachment_count": policy_meta.get("AttachmentCount", 0),
                    "created_date": policy_meta.get("CreateDate", "").isoformat()
                    if hasattr(policy_meta.get("CreateDate", ""), "isoformat")
                    else str(policy_meta.get("CreateDate", "")),
                    "updated_date": policy_meta.get("UpdateDate", "").isoformat()
                    if hasattr(policy_meta.get("UpdateDate", ""), "isoformat")
                    else str(policy_meta.get("UpdateDate", "")),
                })
                summary.total_scanned += 1
                logger.debug(f"Scanned: {policy_name} ({arn})")

            except ClientError as e:
                code = e.response["Error"]["Code"]
                logger.warning(f"Failed to analyze {policy_name} ({arn}): {code} — {e}")
                # FAIL-004: don't silently drop — record the failure explicitly
                summary.total_failed += 1
                summary.failed_policies.append({
                    "policy_name": policy_name,
                    "arn": arn,
                    "error_code": code,
                    "error_message": str(e),
                })

        summary.scan_duration_seconds = time.monotonic() - start
        logger.info(
            f"Scan complete: {summary.total_scanned}/{summary.total_found} policies analyzed, "
            f"{summary.total_failed} failed, {summary.scan_duration_seconds:.1f}s"
        )

        if summary.total_failed > 0:
            logger.warning(
                f"{summary.total_failed} policies could not be analyzed. "
                "Check failed_policies in the report for details."
            )

        return policies, summary

    def _list_all_policies(self) -> Generator[dict, None, None]:
        """
        Paginate through all customer-managed policies.

        FAIL-003: list_policies is paginated at 100 results per page.
        Using get_paginator handles the Marker token automatically.
        Direct list_policies call silently returns only the first page.
        """
        paginator = self._iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):  # Local = customer-managed only
            for policy in page["Policies"]:
                yield policy

    def _get_policy_document(self, arn: str, version_id: str) -> dict[str, Any]:
        """Fetch the policy document for the given ARN and version."""
        response = self._iam.get_policy_version(
            PolicyArn=arn,
            VersionId=version_id,
        )
        return response["PolicyVersion"]["Document"]
