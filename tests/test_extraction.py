from pathlib import Path

import pytest

from hybrid.extraction import ExtractionError, extract_proposals

CONTRACT = (
    Path(__file__).parent.parent / "fixtures" / "scenario-01" / "contract.md"
).read_text()


class FakeLLM:
    def __init__(self, payload):
        self.payload = payload

    def complete_json(self, prompt, document, schema):
        return self.payload


def good_item(**overrides):
    item = {
        "number": "4.2",
        "text": "Customer data stored in Amazon S3 must be accessible only to the DataOps role.",
        "page": 1,
        "data_class": "customer_data",
        "resource_hint": "customer data stored in Amazon S3",
        "principals_hint": ["DataOps role"],
    }
    item.update(overrides)
    return item


def test_extracts_a_proposal_from_the_contract():
    llm = FakeLLM({"obligations": [good_item()]})
    (p,) = extract_proposals(CONTRACT, llm, "t1", "c-001")
    assert p.clause_number == "4.2"
    assert p.clause_id == "c-001-4.2"
    assert p.principals_hint == ("DataOps role",)


def test_empty_list_means_no_obligation():
    assert extract_proposals(CONTRACT, FakeLLM({"obligations": []}), "t1", "c-001") == []


def test_invented_clause_is_rejected():
    fake = good_item(text="All data must be encrypted with a customer-managed key.")
    with pytest.raises(ExtractionError):
        extract_proposals(CONTRACT, FakeLLM({"obligations": [fake]}), "t1", "c-001")


def test_malformed_output_is_rejected():
    bad = good_item()
    del bad["data_class"]
    with pytest.raises(ExtractionError):
        extract_proposals(CONTRACT, FakeLLM({"obligations": [bad]}), "t1", "c-001")
    with pytest.raises(ExtractionError):
        extract_proposals(CONTRACT, FakeLLM({"unexpected": 1}), "t1", "c-001")
