"""Render findings as text, JSON or SARIF 2.1.0."""

from __future__ import annotations

import json

from . import __version__
from .rules import HIGH, LOW, MEDIUM, RULES

SARIF_LEVEL = {HIGH: "error", MEDIUM: "warning", LOW: "note"}
REPO_URL = "https://github.com/TellersTechOrg/plan-skeptic"


def render_text(findings: list, change_count: int) -> str:
    if not findings:
        return f"plan-skeptic: {change_count} resource change(s) reviewed, nothing flagged.\n"
    lines = [f"plan-skeptic: {len(findings)} finding(s) across {change_count} resource change(s)", ""]
    for f in findings:
        rule = RULES[f.rule_id]
        lines.append(f"[{f.severity.upper():6}] {f.rule_id} {rule.name}")
        lines.append(f"         {f.address}: {f.message}")
        lines.append(f"         why a human should look: {rule.why}")
        lines.append("")
    return "\n".join(lines)


def render_json(findings: list, change_count: int) -> str:
    return json.dumps(
        {
            "version": __version__,
            "changes_reviewed": change_count,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "rule": RULES[f.rule_id].name,
                    "severity": f.severity,
                    "address": f.address,
                    "message": f.message,
                }
                for f in findings
            ],
        },
        indent=2,
    ) + "\n"


def render_sarif(findings: list, plan_uri: str) -> str:
    """SARIF for GitHub code scanning.

    Code scanning drops a result that has no physical location, and a plan has
    no source line for a resource, so every result points at the plan file and
    carries the resource address as a logical location.
    """
    rules = [
        {
            "id": r.id,
            "name": r.name,
            "shortDescription": {"text": r.summary},
            "fullDescription": {"text": r.why},
            "helpUri": f"{REPO_URL}#{r.id.lower()}",
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
            "properties": {"security-severity": {HIGH: "8.0", MEDIUM: "5.0", LOW: "2.0"}[r.severity]},
        }
        for r in RULES.values()
    ]
    results = [
        {
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.address}: {f.message}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": plan_uri},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [{"fullyQualifiedName": f.address, "kind": "resource"}],
                }
            ],
            "partialFingerprints": {
                "resourceRule": f"{f.rule_id}:{f.address}" + (f":{f.key}" if f.key else ""),
            },
        }
        for f in findings
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "plan-skeptic",
                        "version": __version__,
                        "informationUri": REPO_URL,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2) + "\n"
