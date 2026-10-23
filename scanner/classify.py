"""Evidence-based classification. Repeated calls to one model are ONE source."""
from __future__ import annotations

import re

# A finding counts as reproduced only if this exact pytest node id is PASSED
# in the same scan. Maintained by hand on purpose.
VERIFICATIONS = [
    {
        "file": "main_vulnerable.py",
        "type": "idor",
        "test_id": "tests/test_idor.py::test_document_ownership[main_vulnerable-True]",
        "proves": "A signed-in non-owner (bob) receives HTTP 200 and the owner's document.",
    },
]

_TEST_LINE = re.compile(
    r"^(?P<id>\S+::\S+)\s+(?P<status>PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)\b",
    re.M,
)


def parse_test_results(test_verification: dict | None) -> dict[str, str]:
    if not isinstance(test_verification, dict):
        return {}
    output = str(test_verification.get("output", ""))
    return {m["id"]: m["status"] for m in _TEST_LINE.finditer(output)}


def confirmations_for(file_key: str, vuln_type: str, test_results: dict) -> list[dict]:
    return [
        {"test_id": v["test_id"], "status": "PASSED", "proves": v["proves"]}
        for v in VERIFICATIONS
        if v["file"].lower() == file_key
        and v["type"] == vuln_type
        and test_results.get(v["test_id"]) == "PASSED"
    ]


def _llm_verdict(record: dict):
    if "validation" in record:
        return record["validation"].get("verdict")
    if "ai_analysis" in record:
        return record["ai_analysis"].get("verdict")
    return None


def classify_group(records: list[dict], confirmations: list[dict], model: str) -> dict:
    triage = [r["triage"] for r in records if "triage" in r]
    untriaged = [r for r in records if "triage" not in r]
    static = [r for r in untriaged if r.get("kind") == "scanner_result"]
    verdicts = [v for v in (_llm_verdict(r) for r in untriaged)
                if v in {"likely", "uncertain", "unlikely"}]

    if verdicts and all(v == "likely" for v in verdicts):
        position = "likely"
    elif verdicts and all(v == "unlikely" for v in verdicts):
        position = "unlikely"
    elif verdicts:
        position = "uncertain"
    else:
        position = None
    llm_leaning = {"likely": "vulnerable", "unlikely": "false_positive"}.get(position)

    if confirmations and static:
        result = ("confirmed", "reproducible_test", None)
    elif triage and static:
        result = ("uncertain", "conflicting_deterministic_evidence", None)
    elif triage:
        if {t["classification"] for t in triage} == {"informational"}:
            result = ("informational", "deterministic_rule", None)
        else:
            result = ("likely_false_positive", "deterministic_rule_out", None)
    elif static and position == "likely":
        result = ("likely_vulnerability", "static_finding+llm", "vulnerable")
    elif static:
        basis = "static_finding_unassessed" if position is None else "static_finding_without_llm_support"
        result = ("uncertain", basis, llm_leaning)
    elif position is not None:
        result = ("uncertain", "llm_only", llm_leaning)
    else:
        result = ("uncertain", "no_assessment", None)

    return {
        "classification": result[0],
        "basis": result[1],
        "leaning": result[2],
        "evidence_sources": {
            "static_tools": sorted({str(r.get("finding", {}).get("source", "Scanner")) for r in static}),
            "deterministic_rules": [
                {"rule": t.get("rule"), "classification": t["classification"]} for t in triage
            ],
            "reproducible_tests": confirmations,
            "llm": {
                "model": model,
                "assessments": len(verdicts),
                "position": position,
                "counts_as_independent_sources": 1 if verdicts else 0,
            },
        },
    }