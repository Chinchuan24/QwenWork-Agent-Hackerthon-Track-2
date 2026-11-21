"""M6 — compliance references must be verified against official sources or
dropped. Verified 2026-11-17: EU AI Act chapter III article titles (artificial
intelligence act.eu / EC service desk), OWASP LLM Top 10 2025 names
(genai.owasp.org), OWASP Agentic Threats & Mitigations v1.0 T-codes, NIST AI
RMF 1.0 subcategory texts (airc.nist.gov). ISO/IEC 42001 clause numbers are
not publicly verifiable -> standard-level reference only, no clause numbers."""
import re

from aegis.app import COMPLIANCE


def _blob():
    return "\n".join(" | ".join(row) for row in COMPLIANCE)


def test_m6_no_training_data_article_for_outgoing_firewall():
    row = next(r for r in COMPLIANCE if r[0].startswith("Data Firewall"))
    assert "Art. 10" not in row[4] and "Article 10" not in row[4]


def test_m6_audit_row_not_llm05():
    row = next(r for r in COMPLIANCE if r[0].startswith("Tamper-evident audit"))
    assert "LLM05" not in row[1]
    assert "T8" in row[1]  # Repudiation & Untraceability is the right agentic threat


def test_m6_explainability_not_misinformation():
    row = next(r for r in COMPLIANCE if r[0].startswith("Explainable"))
    assert "LLM09" not in row[1]


def test_m6_only_verified_eu_articles():
    arts = set(re.findall(r"Art(?:icle)?\.?\s*(\d+)", _blob()))
    assert arts <= {"9", "12", "13", "14", "15"}, arts


def test_m6_only_verified_llm_numbers():
    nums = set(re.findall(r"LLM(\d{2})", _blob()))
    assert nums <= {"01", "02", "05", "06", "10"}, nums


def test_m6_agentic_tcodes_correctly_named():
    blob = _blob()
    for code, name in (("T2", "Tool [Mm]isuse"), ("T3", "Privilege [Cc]ompromise"),
                       ("T8", "Repudiation")):
        if code in blob:
            assert re.search(name, blob), f"{code} used without its verified name"
    assert "T1 Memory/Tool" not in blob  # the old wrong label


def test_m6_iso_clause_numbers_dropped():
    assert "A.6.2" not in _blob()
    for row in COMPLIANCE:
        assert "42001" in row[3]  # standard-level reference kept


def test_m6_nist_subcategories_verified_set():
    refs = set(re.findall(r"(?:GOVERN|MEASURE|MANAGE|MAP)\s+\d\.\d+", _blob()))
    verified = {"GOVERN 1.2", "GOVERN 3.2", "MEASURE 2.7", "MEASURE 2.8",
                "MEASURE 2.9", "MEASURE 2.10", "MANAGE 2.2", "MANAGE 2.4", "MANAGE 4.1"}
    assert refs <= verified, refs - verified