from __future__ import annotations

import re
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .requirements import RequirementProposal

PROMPT = (
    "You read a contract. Extract only obligations about who may access "
    "customer or sensitive data stored in cloud storage. "
    "Quote the clause text exactly as written, never paraphrase. "
    "Use the contract's own wording for resources and principals: do not "
    "invent ARNs, account IDs or technical identifiers. "
    "'page' is the 1-based page of the clause. "
    "If the contract has no such obligation, return an empty list. "
    "Never guess."
)


class ExtractionError(ValueError):
    pass


class LLMClient(Protocol):
    def complete_json(self, prompt: str, document: str, schema: dict) -> dict: ...


class _Item(BaseModel):
    model_config = ConfigDict(extra="forbid")

    number: str
    text: str = Field(min_length=1)
    page: int = Field(default=1, ge=1)
    data_class: str
    resource_hint: str
    principals_hint: list[str]


class _Output(BaseModel):
    model_config = ConfigDict(extra="forbid")

    obligations: list[_Item]


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def extract_proposals(
    document: str, llm: LLMClient, tenant_id: str, contract_id: str
) -> list[RequirementProposal]:
    raw = llm.complete_json(PROMPT, document, _Output.model_json_schema())
    try:
        out = _Output.model_validate(raw)
    except ValidationError as e:
        raise ExtractionError(f"model output is not valid: {e}") from e

    haystack = _norm(document)
    proposals = []
    for item in out.obligations:
        if _norm(item.text) not in haystack:
            raise ExtractionError(f"clause {item.number}: quoted text not found in the contract")
        proposals.append(
            RequirementProposal(
                tenant_id=tenant_id,
                id=f"p-{contract_id}-{item.number}",
                clause_id=f"{contract_id}-{item.number}",
                clause_number=item.number,
                clause_text=item.text,
                page=item.page,
                data_class=item.data_class,
                resource_hint=item.resource_hint,
                principals_hint=tuple(item.principals_hint),
            )
        )
    return proposals
