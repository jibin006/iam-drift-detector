"""
Report Generator

Produces the final JSON report and console summary.

Report includes:
  - Scan metadata (coverage, duration, failures)
  - Risk findings ordered by severity
  - Drift findings by type
  - Failed policies (no silent drops)

Console output surfaces the highest-priority items only.
Full detail is in the JSON report.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from analyzer.drift_comparator import DriftFinding, DriftType
from analyzer.risk_analyzer import PolicyAnalysisResult, Severity
from analyzer.scanner import ScanSummary

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


@dataclass
class ScanReport:
    scan_summary: ScanSummary
    risk_results: list[PolicyAnalysisResult] = field(default_factory=list)
    drift_findings: list[DriftFinding] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        # Sort risk results: CRITICAL first, then by finding count
        sorted_risk = sorted(
            self.risk_results,
            key=lambda r: (
                _SEVERITY_ORDER.index(r.max_severity) if r.max_severity else 99,
                -r.finding_count,
            ),
        )

        return {
            "generated_at": self.generated_at,
            "scan_summary": self.scan_summary.to_dict(),
            "risk_summary": {
                "policies_with_findings": len(self.risk_results),
                "critical": sum(1 for r in self.risk_results if r.max_severity == Severity.CRITICAL),
                "high": sum(1 for r in self.risk_results if r.max_severity == Severity.HIGH),
                "medium": sum(1 for r in self.risk_results if r.max_severity == Severity.MEDIUM),
                "low": sum(1 for r in self.risk_results if r.max_severity == Severity.LOW),
            },
            "drift_summary": {
                "total_drift_findings": len(self.drift_findings),
                "policies_added": sum(1 for d in self.drift_findings if d.drift_type == DriftType.POLICY_ADDED),
                "policies_removed": sum(1 for d in self.drift_findings if d.drift_type == DriftType.POLICY_REMOVED),
                "permissions_expanded": sum(1 for d in self.drift_findings if d.drift_type == DriftType.PERMISSIONS_EXPANDED),
                "conditions_removed": sum(1 for d in self.drift_findings if d.drift_type == DriftType.CONDITION_REMOVED),
            },
            "risk_findings": [r.to_dict() for r in sorted_risk],
            "drift_findings": [d.to_dict() for d in self.drift_findings],
        }


def save_report(report: ScanReport, output_path: str = "iam-scan-report.json") -> None:
    path = Path(output_path)
    with open(path, "w") as f:
        json.dump(report.to_dict(), f, indent=2, default=str)
    logger.info(f"Report saved: {output_path}")


def print_console_summary(report: ScanReport) -> None:
    """Print a human-readable summary to stdout."""
    report_dict = report.to_dict()
    summary = report_dict["scan_summary"]
    risk_summary = report_dict["risk_summary"]
    drift_summary = report_dict["drift_summary"]

    print("\n" + "=" * 65)
    print("IAM DRIFT DETECTOR — SCAN REPORT")
    print("=" * 65)
    print(f"  Policies found:   {summary['total_found']}")
    print(f"  Policies scanned: {summary['total_scanned']} ({summary['coverage_pct']}% coverage)")
    print(f"  Scan duration:    {summary['scan_duration_seconds']}s")
    if summary["total_failed"] > 0:
        print(f"  ⚠  Scan failures: {summary['total_failed']} (see report for details)")

    print("\nRISK FINDINGS")
    print("-" * 40)
    if risk_summary["policies_with_findings"] == 0:
        print("  No risky policies detected.")
    else:
        print(f"  Policies with findings: {risk_summary['policies_with_findings']}")
        for sev in ["critical", "high", "medium", "low"]:
            count = risk_summary[sev]
            if count > 0:
                indicator = "🔴" if sev == "critical" else "🟠" if sev == "high" else "🟡" if sev == "medium" else "⚪"
                print(f"  {indicator} {sev.upper()}: {count} polic{'y' if count == 1 else 'ies'}")

    if report.risk_results:
        print("\n  Top findings:")
        for result in sorted(
            [r for r in report.risk_results if r.max_severity in (Severity.CRITICAL, Severity.HIGH)],
            key=lambda r: _SEVERITY_ORDER.index(r.max_severity),
        )[:5]:
            print(f"    [{result.max_severity.value}] {result.policy_name}")
            for finding in result.findings[:2]:
                print(f"      • {finding.category.value}: {finding.detail[:80]}...")

    print("\nDRIFT FINDINGS")
    print("-" * 40)
    if drift_summary["total_drift_findings"] == 0:
        print("  No drift detected — live state matches baseline.")
    else:
        print(f"  Total drift findings: {drift_summary['total_drift_findings']}")
        if drift_summary["policies_added"] > 0:
            print(f"  ⚠  Unmanaged policies (not in IaC): {drift_summary['policies_added']}")
        if drift_summary["conditions_removed"] > 0:
            print(f"  ⚠  Condition constraints removed: {drift_summary['conditions_removed']}")
        if drift_summary["permissions_expanded"] > 0:
            print(f"  ⚠  Permissions expanded: {drift_summary['permissions_expanded']}")
        if drift_summary["policies_removed"] > 0:
            print(f"     Policies removed from AWS: {drift_summary['policies_removed']}")

    print("\n" + "=" * 65)
