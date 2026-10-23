from scanner.ai_analyzer import build_consolidated_findings
from scanner.classify import classify_group, confirmations_for, parse_test_results

VULN_ID = "tests/test_idor.py::test_document_ownership[main_vulnerable-True]"
PYTEST_OUTPUT = f"""\
collecting ... collected 3 items

{VULN_ID} PASSED [ 33%]
tests/test_idor.py::test_document_ownership[main-False] PASSED           [ 66%]
tests/test_idor.py::test_owner_can_read_own_document PASSED              [100%]
"""


def _scanner(source="PatchProof-IDOR", verdict="likely"):
    return {"kind": "scanner_result", "finding": {"source": source},
            "ai_analysis": {"verdict": verdict}}


def _candidate(verdict):
    return {"kind": "ai_discovery", "validation": {"verdict": verdict}}


def _triaged(classification):
    return {"kind": "scanner_result", "finding": {"source": "Bandit"},
            "triage": {"classification": classification, "rule": "r"}}


def test_confirmation_needs_the_exact_test_to_pass():
    results = parse_test_results({"output": PYTEST_OUTPUT})
    assert results[VULN_ID] == "PASSED"
    assert len(confirmations_for("main_vulnerable.py", "idor", results)) == 1
    assert confirmations_for("main_vulnerable.py", "idor", {VULN_ID: "FAILED"}) == []
    assert confirmations_for("main.py", "idor", results) == []
    assert confirmations_for("main_vulnerable.py", "sqli", results) == []


def test_confirmed_needs_static_support():
    conf = [{"test_id": VULN_ID}]
    assert classify_group([_scanner(), _candidate("likely")], conf, "m")["classification"] == "confirmed"
    assert classify_group([_candidate("likely")], conf, "m")["classification"] == "uncertain"


def test_repeated_same_model_verdicts_are_one_source():
    r = classify_group([_candidate("likely")] * 3, [], "m")
    assert (r["classification"], r["basis"], r["leaning"]) == ("uncertain", "llm_only", "vulnerable")
    assert r["evidence_sources"]["llm"]["assessments"] == 3
    assert r["evidence_sources"]["llm"]["counts_as_independent_sources"] == 1


def test_static_finding_plus_llm_likely():
    r = classify_group([_scanner("Bandit", "likely")], [], "m")
    assert r["classification"] == "likely_vulnerability"


def test_static_finding_with_llm_unlikely_stays_uncertain():
    r = classify_group([_scanner("Bandit", "unlikely")], [], "m")
    assert (r["classification"], r["leaning"]) == ("uncertain", "false_positive")


def test_deterministic_rule_out_beats_llm_likely():
    r = classify_group([_triaged("likely_false_positive"), _candidate("likely")], [], "m")
    assert r["classification"] == "likely_false_positive"


def test_informational_only():
    assert classify_group([_triaged("informational")] * 2, [], "m")["classification"] == "informational"


def test_conflicting_deterministic_evidence_is_uncertain():
    triaged = {**_candidate("likely"), "triage": {"classification": "likely_false_positive", "rule": "r"}}
    r = classify_group([_scanner(), triaged], [], "m")
    assert (r["classification"], r["basis"]) == ("uncertain", "conflicting_deterministic_evidence")


def test_consolidation_confirms_only_with_a_passing_test(tmp_path):
    item = {
        "finding": {"source": "PatchProof-IDOR", "category": "Potential IDOR",
                    "severity": "WARNING", "line": 40, "message": "idor",
                    "file": str(tmp_path / "main_vulnerable.py")},
        "ai_analysis": {"verdict": "likely", "vulnerability_type": "IDOR"},
    }
    report = {"target": str(tmp_path)}
    confirmed = build_consolidated_findings(report, [item], [], {VULN_ID: "PASSED"})
    unconfirmed = build_consolidated_findings(report, [item], [], {})
    assert confirmed[0]["classification"] == "confirmed"
    assert unconfirmed[0]["classification"] == "likely_vulnerability"