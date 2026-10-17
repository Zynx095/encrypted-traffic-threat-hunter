"""Acceptance smoke test: every parameterless GET route answers without a server error.

Routes that need git-ignored research data must answer 404 with a message, never 500, so the
API behaves honestly on a clean checkout as well as on a machine with local data.
"""
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from backend.main import app

GET_ROUTES = sorted({r.path for r in app.routes
                     if isinstance(r, APIRoute) and "GET" in r.methods and "{" not in r.path})


def test_route_inventory_includes_all_phases():
    for path in ("/api/health", "/api/sensors/status", "/api/research/claims", "/api/research/models",
                 "/api/research/inference/status", "/api/live-stream/status"):
        assert path in GET_ROUTES


@pytest.mark.parametrize("path", GET_ROUTES)
def test_get_route_never_returns_server_error(path):
    resp = TestClient(app).get(path)
    assert resp.status_code < 500, (path, resp.status_code, resp.text[:300])
    if resp.status_code >= 400:
        assert "detail" in resp.json()
