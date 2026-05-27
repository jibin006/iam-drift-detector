"""
AI Explainer — Gemini

Produces human-readable explanations for risk and drift findings.

Design decisions:
  - Non-blocking: if Gemini fails, findings are saved with ai_explanation=null.
    The scan does not fail. See FAILURES.md FAIL-007.
  - Account ID stripped from policy ARNs before sending. IAM policy structure
    is sent but not the account-level identifiers.
  - Decoupled from finding collection: enrichment runs in a second pass after
    all findings are collected. Finding collection is the critical path.
  - Rate-limited: sleeps between calls to stay within Gemini free tier limits.

See DECISIONS.md ADR-003 for Gemini vs Bedrock reasoning and data privacy trade-off.
"""

from __future__ import annotations

import logging
import re
import time

import google.generativeai as genai

from analyzer.risk_analyzer import PolicyAnalysisResult, RiskFinding, Severity
from analyzer.drift_comparator import DriftFinding

logger = logging.getLogger(__name__)

# Delay between Gemini API calls to avoid rate limiting
_INTER_CALL_DELAY_SECONDS = 1.0


def _strip_account_id(text: str) -> str:
    """
    Remove 12-digit AWS account IDs from text before sending to external API.

    arn:aws:iam::123456789012:policy/MyPolicy → arn:aws:iam::ACCOUNT_ID:policy/MyPolicy

    This reduces the sensitivity of data sent to Gemini.
    IAM policy document structure is still sent — the trade-off is documented.
    See DECISIONS.md ADR-003.
    """
    return re.sub(r"\b\d{12}\b", "ACCOUNT_ID", text)


class GeminiExplainer:
    """
    Enriches findings with AI-generated explanations and remediation guidance.

    Usage:
        explainer = GeminiExplainer(api_key=os.environ["GEMINI_API_KEY"])
        enriched = explainer.enrich_risk_result(policy_result)
    """

    def __init__(self, api_key: str):
        if not api_key:
            raise ValueError(
                "Gemini API key is required. Set GEMINI_API_KEY environment variable. "
                "Get a key at https://makersuite.google.com/app/apikey"
            )
        genai.configure(api_key=api_key)
        self._model = genai.GenerativeModel("gemini-1.5-flash")

    def enrich_risk_result(self, result: PolicyAnalysisResult) -> PolicyAnalysisResult:
        """
        Add AI explanation to a policy risk analysis result.

        Non-blocking: if Gemini fails, sets ai_explanation_error and returns
        the result unchanged. Scan continues.
        """
        if not result.has_findings:
            return result

        try:
            explanation = self._explain_risk(result.policy_name, result.findings)
            result.ai_explanation = explanation
        except Exception as exc:
            logger.warning(
                f"AI explanation failed for {result.policy_name}: {exc}. "
                "Finding saved without explanation."
            )
            result.ai_explanation_error = str(exc)

        time.sleep(_INTER_CALL_DELAY_SECONDS)
        return result

    def enrich_drift_finding(self, finding: DriftFinding) -> DriftFinding:
        """Add AI explanation to a drift finding. Non-blocking."""
        try:
            finding.ai_explanation = self._explain_drift(finding)
        except Exception as exc:
            logger.warning(f"AI explanation failed for drift finding {finding.policy_name}: {exc}")
            finding.ai_explanation_error = str(exc)

        time.sleep(_INTER_CALL_DELAY_SECONDS)
        return finding

    def _explain_risk(self, policy_name: str, findings: list[RiskFinding]) -> str:
        """Generate explanation for risk findings."""
        # Strip account IDs from finding details before sending
        findings_text = "\n".join([
            f"- [{f.severity.value}] {f.category.value}: {_strip_account_id(f.detail)}"
            for f in findings
        ])

        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)

        prompt = f"""You are a senior AWS cloud security engineer reviewing IAM policies.
Policy name: {policy_name}
Findings ({len(findings)} total, {critical_count} CRITICAL, {high_count} HIGH):
{findings_text}

Provide:
1. One sentence summary of the overall risk level and what an attacker could do with this policy
2. The most dangerous finding and why (be specific about blast radius)
3. The single most important remediation action

Be direct. No preamble. No markdown headers. Engineers reading this already know IAM basics.
Keep total response under 150 words."""

        response = self._model.generate_content(prompt)
        return response.text if response.text else "AI explanation unavailable."

    def _explain_drift(self, finding: DriftFinding) -> str:
        """Generate explanation for a drift finding."""
        prompt = f"""You are a senior AWS cloud security engineer reviewing IAM configuration drift.
Policy: {finding.policy_name}
Drift type: {finding.drift_type.value}
Detail: {_strip_account_id(finding.detail)}

In 2-3 sentences: explain the security implication of this drift and the recommended action.
Be direct. No preamble."""

        response = self._model.generate_content(prompt)
        return response.text if response.text else "AI explanation unavailable."
