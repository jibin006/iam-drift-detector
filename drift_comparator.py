"""
IAM Drift Comparator

Compares live IAM policy state against a stored baseline.

This is the "Drift" in "IAM Drift Detector" — the capability the original
tool named itself after but never implemented.

Drift = the gap between what your IaC declares and what AWS is enforcing.
Risk = dangerous permissions, regardless of whether they drifted.
These are different problems. Both are important. They're not the same.

Baseline format: JSON file produced by the baseline generator. Checked into
git alongside Terraform. Treat it as code — every change is a commit.
See DECISIONS.md ADR-004.

Drift types detected:
  POLICY_ADDED      - exists in AWS, not in baseline (unmanaged, out of IaC)
  POLICY_REMOVED    - in baseline, gone from AWS (deletion not tracked)
  PERMISSIONS_EXPANDED  - live policy has actions/resources baseline didn't
  PERMISSIONS_REDUCED   - live is more restrictive (track it, usually fine)
  CONDITION_REMOVED     - baseline had condition constraints, live dropped them
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class DriftType(str, Enum):
    POLICY_ADDED = "POLICY_ADDED"
    POLICY_REMOVED = "POLICY_REMOVED"
    PERMISSIONS_EXPANDED = "PERMISSIONS_EXPANDED"
    PERMISSIONS_REDUCED = "PERMISSIONS_REDUCED"
    CONDITION_REMOVED = "CONDITION_REMOVED"


@dataclass
class DriftFinding:
    policy_name: str
    policy_arn: str
    drift_type: DriftType
    detail: str
    baseline_state: dict | None = None
    live_state: dict | None = None

    def to_dict(self) -> dict:
        return {
            "policy_name": self.policy_name,
            "policy_arn": self.policy_arn,
            "drift_type": self.drift_type.value,
            "detail": self.detail,
            "baseline_state": self.baseline_state,
            "live_state": self.live_state,
        }


class IAMDriftComparator:
    """
    Compares live IAM policy documents against a stored baseline.

    Usage:
        comparator = IAMDriftComparator()
        baseline = comparator.load_baseline("baselines/prod-baseline.json")

        findings = comparator.compare(
            policy_name="MyPolicy",
            policy_arn="arn:aws:iam::123456789012:policy/MyPolicy",
            live_document=live_doc,
            baseline=baseline,
        )

    Generating a baseline:
        baseline = comparator.generate_baseline(live_policies_dict)
        comparator.save_baseline(baseline, "baselines/prod-baseline.json")
    """

    def load_baseline(self, path: str) -> dict[str, Any]:
        """
        Load a baseline JSON file.

        Baseline structure:
        {
            "generated_at": "ISO timestamp",
            "policies": {
                "arn:aws:iam::123456789012:policy/PolicyName": {
                    "policy_name": "PolicyName",
                    "document": { <policy document> }
                }
            }
        }
        """
        baseline_path = Path(path)
        if not baseline_path.exists():
            raise FileNotFoundError(
                f"Baseline not found: {path}. "
                "Generate one with: python main.py --mode baseline --output baselines/prod-baseline.json"
            )
        with open(baseline_path) as f:
            return json.load(f)

    def save_baseline(self, baseline: dict[str, Any], path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(baseline, f, indent=2, default=str)

    def generate_baseline(
        self, live_policies: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """
        Generate a baseline from current live IAM state.

        Call this after a clean Terraform apply. The output is the
        "expected state" snapshot — commit it alongside the Terraform code.
        """
        from datetime import datetime, timezone

        policies_map = {}
        for entry in live_policies:
            arn = entry["arn"]
            policies_map[arn] = {
                "policy_name": entry["policy_name"],
                "document": entry["document"],
            }

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "policy_count": len(policies_map),
            "policies": policies_map,
        }

    def compare_all(
        self,
        live_policies: list[dict[str, Any]],
        baseline: dict[str, Any],
    ) -> list[DriftFinding]:
        """
        Compare all live policies against baseline. Returns all drift findings.

        live_policies: list of {"arn": ..., "policy_name": ..., "document": ...}
        baseline: loaded from load_baseline()
        """
        findings: list[DriftFinding] = []
        baseline_policies: dict[str, Any] = baseline.get("policies", {})

        live_by_arn = {p["arn"]: p for p in live_policies}

        # POLICY_ADDED: in live, not in baseline
        for arn, live_entry in live_by_arn.items():
            if arn not in baseline_policies:
                findings.append(DriftFinding(
                    policy_name=live_entry["policy_name"],
                    policy_arn=arn,
                    drift_type=DriftType.POLICY_ADDED,
                    detail=(
                        f"Policy '{live_entry['policy_name']}' exists in AWS but is not in the IaC baseline. "
                        "It was created outside of Terraform — either manually in the console or via CLI. "
                        "It is not version-controlled."
                    ),
                    live_state=live_entry["document"],
                ))

        # POLICY_REMOVED: in baseline, not in live
        for arn, baseline_entry in baseline_policies.items():
            if arn not in live_by_arn:
                findings.append(DriftFinding(
                    policy_name=baseline_entry["policy_name"],
                    policy_arn=arn,
                    drift_type=DriftType.POLICY_REMOVED,
                    detail=(
                        f"Policy '{baseline_entry['policy_name']}' is in the baseline but no longer exists in AWS. "
                        "It was deleted outside of Terraform. "
                        "If this was intentional, update the baseline."
                    ),
                    baseline_state=baseline_entry["document"],
                ))

        # Permission and condition drift for policies present in both
        for arn, live_entry in live_by_arn.items():
            if arn not in baseline_policies:
                continue  # already flagged as POLICY_ADDED
            findings.extend(self.compare_single(
                policy_name=live_entry["policy_name"],
                policy_arn=arn,
                live_document=live_entry["document"],
                baseline_document=baseline_policies[arn]["document"],
            ))

        return findings

    def compare_single(
        self,
        policy_name: str,
        policy_arn: str,
        live_document: dict[str, Any],
        baseline_document: dict[str, Any],
    ) -> list[DriftFinding]:
        """
        Compare one policy's live document against its baseline document.

        Structural comparison at the statement level:
        - Expanded actions/resources = PERMISSIONS_EXPANDED
        - Removed conditions = CONDITION_REMOVED (most dangerous drift)
        - Reduced actions/resources = PERMISSIONS_REDUCED
        """
        findings: list[DriftFinding] = []

        live_stmts = self._index_statements(live_document)
        baseline_stmts = self._index_statements(baseline_document)

        for sid, baseline_stmt in baseline_stmts.items():
            if sid not in live_stmts:
                continue  # statement removed — PERMISSIONS_REDUCED, tracked below

            live_stmt = live_stmts[sid]
            baseline_actions = set(self._normalize(baseline_stmt.get("Action", [])))
            live_actions = set(self._normalize(live_stmt.get("Action", [])))
            baseline_resources = set(self._normalize(baseline_stmt.get("Resource", [])))
            live_resources = set(self._normalize(live_stmt.get("Resource", [])))

            added_actions = live_actions - baseline_actions
            added_resources = live_resources - baseline_resources
            removed_actions = baseline_actions - live_actions

            # Permissions expanded: new actions or resources added
            if added_actions or added_resources:
                findings.append(DriftFinding(
                    policy_name=policy_name,
                    policy_arn=policy_arn,
                    drift_type=DriftType.PERMISSIONS_EXPANDED,
                    detail=(
                        f"Statement '{sid}' has expanded permissions vs baseline. "
                        f"{'Added actions: ' + str(sorted(added_actions)) + '. ' if added_actions else ''}"
                        f"{'Added resources: ' + str(sorted(added_resources)) + '. ' if added_resources else ''}"
                        "These permissions were not in the Terraform-managed baseline."
                    ),
                    baseline_state=baseline_stmt,
                    live_state=live_stmt,
                ))

            # Condition removed: more dangerous than permissions expanded
            # A condition removal can expand effective access without changing the action list
            baseline_conditions = baseline_stmt.get("Condition", {})
            live_conditions = live_stmt.get("Condition", {})

            if baseline_conditions and not live_conditions:
                findings.append(DriftFinding(
                    policy_name=policy_name,
                    policy_arn=policy_arn,
                    drift_type=DriftType.CONDITION_REMOVED,
                    detail=(
                        f"Statement '{sid}' had condition constraints in baseline that are gone in live. "
                        f"Removed conditions: {baseline_conditions}. "
                        "Removing conditions expands effective access even when the action list is unchanged. "
                        "Example: removing aws:MultiFactorAuthPresent condition removes MFA enforcement."
                    ),
                    baseline_state=baseline_stmt,
                    live_state=live_stmt,
                ))
            elif baseline_conditions and live_conditions:
                # Check for partial condition removal
                removed_condition_keys = set(baseline_conditions.keys()) - set(live_conditions.keys())
                if removed_condition_keys:
                    findings.append(DriftFinding(
                        policy_name=policy_name,
                        policy_arn=policy_arn,
                        drift_type=DriftType.CONDITION_REMOVED,
                        detail=(
                            f"Statement '{sid}' is missing condition keys vs baseline: {removed_condition_keys}. "
                            "Partial condition removal still expands access."
                        ),
                        baseline_state=baseline_stmt,
                        live_state=live_stmt,
                    ))

            # Permissions reduced: track but lower urgency
            if removed_actions:
                findings.append(DriftFinding(
                    policy_name=policy_name,
                    policy_arn=policy_arn,
                    drift_type=DriftType.PERMISSIONS_REDUCED,
                    detail=(
                        f"Statement '{sid}' is more restrictive than baseline. "
                        f"Removed actions: {sorted(removed_actions)}. "
                        "Usually acceptable — document the change and update the baseline."
                    ),
                    baseline_state=baseline_stmt,
                    live_state=live_stmt,
                ))

        return findings

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _normalize(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return value
        return []

    @staticmethod
    def _index_statements(document: dict[str, Any]) -> dict[str, dict]:
        """
        Index policy statements by Sid for comparison.

        Policies without Sid are harder to diff precisely — they're indexed
        by position. Not ideal but the only option for Sid-less policies.
        """
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        indexed = {}
        for i, stmt in enumerate(statements):
            sid = stmt.get("Sid") or f"_stmt_{i}"
            indexed[sid] = stmt
        return indexed
