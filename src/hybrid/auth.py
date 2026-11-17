"""Identity and roles resolved from an API key.

The tenant, the user and the role always come from the API key held by the
server, never from the request body. This module only defines the types; the
lookup lives in ``Store.principal_for_key``.
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Role(StrEnum):
    ADMIN = "admin"
    REVIEWER = "reviewer"
    VIEWER = "viewer"


class Principal(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str
    user_id: str
    role: Role
