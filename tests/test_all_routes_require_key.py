"""Safety net: every API route must reject requests without an API key.

If you add an endpoint and forget the auth dependency, this test fails.
Intentionally public paths must be listed in PUBLIC_PATHS (keep it tiny).
"""

import re

import pytest

pytest.importorskip("fastapi")

from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from hybrid.api import create_app  # noqa: E402
from hybrid.store import Store  # noqa: E402

PUBLIC_PATHS: set[str] = set()  # e.g. {"/health"} if you add one on purpose


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "x", path)


def _calls(app):
    for route in app.routes:
        if not isinstance(route, APIRoute) or route.path in PUBLIC_PATHS:
            continue
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            yield method, route.path


@pytest.fixture
def client():
    app = create_app(Store(), llm_factory=lambda: None)
    return app, TestClient(app)


def test_every_route_rejects_requests_without_a_key(client):
    app, http = client
    checked = []
    for method, path in _calls(app):
        response = http.request(method, _concrete(path))
        assert response.status_code == 401, (
            f"{method} {path} answered {response.status_code} "
            "without an API key (expected 401)"
        )
        checked.append((method, path))
    assert len(checked) >= 8, checked  # the sweep really ran over the API


def test_a_garbage_key_is_rejected_everywhere(client):
    app, http = client
    for method, path in _calls(app):
        response = http.request(
            method, _concrete(path), headers={"X-API-Key": "not-a-real-key"}
        )
        assert response.status_code == 401, f"{method} {path}"
