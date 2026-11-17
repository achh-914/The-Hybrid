import os
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .extraction import ExtractionError, extract_proposals
from .requirements import Approval, approve, reject
from .store import Store


class ContractIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
    text: str = Field(min_length=1, max_length=200_000)


class RejectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reviewer: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=500)


def _default_llm():
    from .providers.gemini import GeminiClient

    return GeminiClient()


def create_app(store: Store, llm_factory=None) -> FastAPI:
    factory = llm_factory or _default_llm
    app = FastAPI(title="THE HYBRID")

    def current_tenant(x_api_key: str | None = Header(default=None)) -> str:
        tenant_id = store.tenant_for_key(x_api_key) if x_api_key else None
        if tenant_id is None:
            raise HTTPException(status_code=401, detail="missing or invalid API key")
        return tenant_id

    Tenant = Annotated[str, Depends(current_tenant)]

    @app.post("/contracts", status_code=201)
    def upload_contract(body: ContractIn, tenant_id: Tenant):
        try:
            proposals = extract_proposals(body.text, factory(), tenant_id, body.contract_id)
        except ExtractionError as e:
            raise HTTPException(status_code=422, detail=f"extraction failed: {e}")
        except Exception:
            raise HTTPException(status_code=502, detail="extraction service unavailable")
        store.add_proposals(tenant_id, proposals)
        return {"proposals": [p.model_dump(mode="json") for p in proposals]}

    @app.get("/proposals")
    def list_proposals(tenant_id: Tenant):
        return [
            {"status": s, **p.model_dump(mode="json")}
            for s, p in store.list_proposals(tenant_id)
        ]

    @app.post("/proposals/{proposal_id}/approve")
    def approve_proposal(proposal_id: str, approval: Approval, tenant_id: Tenant):
        found = store.get_proposal(tenant_id, proposal_id)
        if found is None:
            raise HTTPException(status_code=404, detail="proposal not found")
        status, proposal = found
        if status != "pending":
            raise HTTPException(status_code=409, detail=f"proposal already {status}")
        requirement, entry = approve(proposal, approval)
        if not store.decide(tenant_id, proposal_id, "approved", requirement, entry):
            raise HTTPException(status_code=409, detail="proposal already decided")
        return requirement.model_dump(mode="json")

    @app.post("/proposals/{proposal_id}/reject")
    def reject_proposal(proposal_id: str, body: RejectIn, tenant_id: Tenant):
        found = store.get_proposal(tenant_id, proposal_id)
        if found is None:
            raise HTTPException(status_code=404, detail="proposal not found")
        status, proposal = found
        if status != "pending":
            raise HTTPException(status_code=409, detail=f"proposal already {status}")
        entry = reject(proposal, body.reviewer, body.reason)
        if not store.decide(tenant_id, proposal_id, "rejected", None, entry):
            raise HTTPException(status_code=409, detail="proposal already decided")
        return {"status": "rejected"}

    @app.get("/requirements")
    def list_requirements(tenant_id: Tenant):
        return [r.model_dump(mode="json") for r in store.list_requirements(tenant_id)]

    @app.get("/audit")
    def list_audit(tenant_id: Tenant):
        return [e.model_dump(mode="json") for e in store.list_audit(tenant_id)]

    return app


def create_default_app() -> FastAPI:
    return create_app(Store(os.getenv("HYBRID_DB", "hybrid.db")))
