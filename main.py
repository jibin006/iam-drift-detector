#!/usr/bin/env python3
"""
IAM Drift Detector — Main Entry Point

Modes:
  risk      — scan for risky IAM policies (multi-signal, not just wildcards)
  drift     — compare live state against IaC baseline
  full      — both risk scan and drift comparison
  baseline  — generate a new baseline from current live state

Usage:
  python main.py --mode risk
  python main.py --mode drift --baseline baselines/prod-baseline.json
  python main.py --mode full --baseline baselines/prod-baseline.json
  python main.py --mode baseline --output baselines/prod-baseline.json
"""

import argparse
import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "msg": "%(message)s"}',
)
logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="IAM Drift Detector — risk analysis and drift detection for AWS IAM policies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["risk", "drift", "full", "baseline"],
        default="risk",
        help="Scan mode (default: risk)",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Path to baseline JSON for drift comparison (required for drift/full modes)",
    )
    parser.add_argument(
        "--output",
        default="iam-scan-report.json",
        help="Output path for report JSON (default: iam-scan-report.json)",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI enrichment (useful when Gemini API key is unavailable or for faster scans)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Validate credentials before doing any work
    gemini_key = os.environ.get("GEMINI_API_KEY")
    if not args.no_ai and not gemini_key:
        print(
            "ERROR: GEMINI_API_KEY environment variable not set.\n"
            "Run with --no-ai to skip AI enrichment, or set the key:\n"
            "  export GEMINI_API_KEY=your_key_here\n"
            "\nNEVER hardcode the key in source code. See FAILURES.md FAIL-005.",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.mode in ("drift", "full") and not args.baseline:
        print(
            "ERROR: --baseline is required for drift and full modes.\n"
            "Generate a baseline first:\n"
            "  python main.py --mode baseline --output baselines/prod-baseline.json",
            file=sys.stderr,
        )
        sys.exit(1)

    # Lazy imports — keep startup fast
    from analyzer.scanner import IAMScanner
    from analyzer.risk_analyzer import IAMRiskAnalyzer
    from analyzer.drift_comparator import IAMDriftComparator
    from reporter.report import ScanReport, save_report, print_console_summary

    scanner = IAMScanner(region=args.region)
    risk_analyzer = IAMRiskAnalyzer()
    drift_comparator = IAMDriftComparator()

    # Step 1: Scan AWS for live policies
    print(f"\nScanning AWS IAM policies (region: {args.region})...")
    live_policies, scan_summary = scanner.scan()

    risk_results = []
    drift_findings = []

    # Step 2: Baseline generation mode
    if args.mode == "baseline":
        baseline = drift_comparator.generate_baseline(live_policies)
        drift_comparator.save_baseline(baseline, args.output)
        print(f"\nBaseline saved: {args.output}")
        print(f"  Policies captured: {baseline['policy_count']}")
        print(f"  Generated at: {baseline['generated_at']}")
        print("\nCommit this file alongside your Terraform code.")
        print("Treat it as IaC — every change should be a reviewed commit.")
        return

    # Step 3: Risk analysis
    if args.mode in ("risk", "full"):
        print(f"Analyzing {len(live_policies)} policies for risk signals...")
        for policy in live_policies:
            result = risk_analyzer.analyze(
                policy_name=policy["policy_name"],
                policy_arn=policy["arn"],
                document=policy["document"],
            )
            if result.has_findings:
                risk_results.append(result)

        print(f"  Risk scan complete: {len(risk_results)} policies with findings")

    # Step 4: Drift comparison
    if args.mode in ("drift", "full"):
        print(f"Comparing live state against baseline: {args.baseline}...")
        try:
            baseline = drift_comparator.load_baseline(args.baseline)
            drift_findings = drift_comparator.compare_all(live_policies, baseline)
            print(f"  Drift scan complete: {len(drift_findings)} drift findings")
        except FileNotFoundError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

    # Step 5: AI enrichment (second pass — decoupled from finding collection)
    # FAIL-007: AI enrichment was in the hot path before — it blocked the entire scan.
    # Now it runs after all findings are collected. If Gemini fails, findings are saved anyway.
    if not args.no_ai and gemini_key and (risk_results or drift_findings):
        from explainer.gemini_client import GeminiExplainer
        explainer = GeminiExplainer(api_key=gemini_key)

        print(f"Enriching {len(risk_results)} risk findings with AI explanations...")
        for result in risk_results:
            result = explainer.enrich_risk_result(result)

        if drift_findings:
            print(f"Enriching {len(drift_findings)} drift findings with AI explanations...")
            for finding in drift_findings:
                explainer.enrich_drift_finding(finding)

    # Step 6: Report
    report = ScanReport(
        scan_summary=scan_summary,
        risk_results=risk_results,
        drift_findings=drift_findings,
    )

    print_console_summary(report)
    save_report(report, args.output)
    print(f"\nFull report: {args.output}")

    # Exit code: non-zero if CRITICAL findings exist (useful for CI/CD)
    has_critical = any(
        result.max_severity and result.max_severity.value == "CRITICAL"
        for result in risk_results
    )
    if has_critical:
        print("⚠  CRITICAL findings detected. Review before merging.", file=sys.stderr)
        sys.exit(2)  # 2 = findings, not crash


if __name__ == "__main__":
    main()
