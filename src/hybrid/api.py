import os
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from .auth import Principal, Role
from .scans import register_scan_routes
from .aws_routes import register_aws_routes
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

    def current_principal(x_api_key: str | None = Header(default=None)) -> Principal:
        principal = store.principal_for_key(x_api_key) if x_api_key else None
        if principal is None:
            raise HTTPException(status_code=401, detail="missing or invalid API key")
        return principal

    def current_tenant(principal: Principal = Depends(current_principal)) -> str:
        return principal.tenant_id

    def require_roles(*allowed: Role):
        def dependency(principal: Principal = Depends(current_principal)) -> Principal:
            if principal.role not in allowed:
                raise HTTPException(status_code=403, detail="insufficient role")
            return principal

        return dependency

    def admin_tenant(principal: Principal = Depends(require_roles(Role.ADMIN))) -> str:
        return principal.tenant_id

    Tenant = Annotated[str, Depends(current_tenant)]
    ReviewerP = Annotated[Principal, Depends(require_roles(Role.REVIEWER, Role.ADMIN))]

    @app.post("/contracts", status_code=201)
    def upload_contract(body: ContractIn, principal: ReviewerP):
        tenant_id = principal.tenant_id
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
    def approve_proposal(proposal_id: str, approval: Approval, principal: ReviewerP):
        tenant_id = principal.tenant_id
        approval = approval.model_copy(update={"reviewer": principal.user_id})
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
    def reject_proposal(proposal_id: str, body: RejectIn, principal: ReviewerP):
        tenant_id = principal.tenant_id
        found = store.get_proposal(tenant_id, proposal_id)
        if found is None:
            raise HTTPException(status_code=404, detail="proposal not found")
        status, proposal = found
        if status != "pending":
            raise HTTPException(status_code=409, detail=f"proposal already {status}")
        entry = reject(proposal, principal.user_id, body.reason)
        if not store.decide(tenant_id, proposal_id, "rejected", None, entry):
            raise HTTPException(status_code=409, detail="proposal already decided")
        return {"status": "rejected"}

    @app.get("/requirements")
    def list_requirements(tenant_id: Tenant):
        return [r.model_dump(mode="json") for r in store.list_requirements(tenant_id)]

    @app.get("/audit")
    def list_audit(tenant_id: Tenant):
        return [e.model_dump(mode="json") for e in store.list_audit(tenant_id)]

    register_scan_routes(app, store, current_tenant, admin_tenant)
    register_aws_routes(app, store, admin_tenant)
    return app


def create_default_app() -> FastAPI:
    return create_app(Store(os.getenv("HYBRID_DB", "hybrid.db")))
