"""Contract-shaped HTTP tests derived from Broadcom ZTNA API examples."""

from __future__ import annotations

import json

import httpx
import pytest

from symantec_ztna_aiops import ops
from symantec_ztna_aiops.connection import ZtnaConnection, ZtnaError


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("SYMANTEC_ZTNA_URL", "https://api.example.luminatesec.com")
    monkeypatch.setenv("SYMANTEC_ZTNA_CLIENT_ID", "client")
    monkeypatch.setenv("SYMANTEC_ZTNA_CLIENT_SECRET", "secret")


def connection(handler) -> ZtnaConnection:
    return ZtnaConnection(httpx.Client(
        base_url="https://api.example.luminatesec.com", transport=httpx.MockTransport(handler)
    ))


def token(value="token1"):
    return httpx.Response(200, json={"access_token": value, "expires_in": 3600})


def test_oauth_and_page_contract():
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path == "/v1/oauth/token":
            return token()
        assert request.url.path == "/v2/sites"
        return httpx.Response(200, json={"content": [{"id": "s1"}], "number": 2,
                                         "last": False, "totalElements": 101})

    result = ops.sites(connection(handler), limit=20, page=2, filter_text="office")
    assert seen[0].method == "POST"
    assert seen[0].headers["authorization"].startswith("Basic ")
    assert seen[1].headers["authorization"] == "Bearer token1"
    assert seen[1].url.params["size"] == "20"
    assert seen[1].url.params["page"] == "2"
    assert seen[1].url.params["filter"] == "office"
    assert result == {"items": [{"id": "s1"}], "returned": 1, "limit": 20,
                      "page": 2, "truncated": True, "nextPage": 3, "totalReported": 101}


def test_401_refreshes_once_and_login_rejection_backs_off():
    calls = {"auth": 0, "api": 0}

    def handler(request):
        if request.url.path == "/v1/oauth/token":
            calls["auth"] += 1
            return token(f"token{calls['auth']}")
        calls["api"] += 1
        if calls["api"] == 2:
            return httpx.Response(401, json={"secret": "never log"})
        return httpx.Response(200, json={"content": [], "number": 0,
                                         "last": True, "totalElements": 0})

    conn = connection(handler)
    ops.sites(conn)
    ops.sites(conn)
    assert calls == {"auth": 2, "api": 3}

    def rejected(_):
        return httpx.Response(401, json={"secret": "never log"})

    conn = connection(rejected)
    with pytest.raises(ZtnaError, match="rejected") as exc:
        ops.sites(conn)
    assert "never log" not in str(exc.value)
    with pytest.raises(ZtnaError, match="recently"):
        ops.sites(conn)


def test_page_metadata_must_be_real():
    def bad(request):
        if request.url.path == "/v1/oauth/token":
            return token()
        return httpx.Response(200, json={"content": [], "number": 1,
                                         "last": False, "totalElements": 10})

    with pytest.raises(ZtnaError, match="metadata"):
        ops.connectors(connection(bad))


def test_audit_query_only_post_and_measured_truncation():
    seen = []

    def handler(request):
        if request.url.path == "/v1/oauth/token":
            return token()
        seen.append(request)
        return httpx.Response(200, json={"Hits": 3, "Logs": [
            {"Id": "a", "SearchAfterValues": [101, "a"]},
            {"Id": "b", "SearchAfterValues": [102, "b"]},
            {"Id": "c", "SearchAfterValues": [103, "c"]},
        ]})

    result = ops.audit_logs(connection(handler), 1_000, 2_000, limit=2,
                            free_text="user@example.com")
    body = json.loads(seen[0].content)
    assert seen[0].method == "POST" and seen[0].url.path == "/v2/logs/audit"
    assert body["size"] == 3
    assert body["query"] == {"from_date": 1000, "to_date": 2000,
                             "free_text": "user@example.com"}
    assert result["items"] == [{"Id": "a", "SearchAfterValues": [101, "a"]},
                               {"Id": "b", "SearchAfterValues": [102, "b"]}]
    assert result["truncated"] is True
    assert result["nextCursor"] == [102, "b"]


def test_audit_missing_cursor_is_error():
    def handler(request):
        if request.url.path == "/v1/oauth/token":
            return token()
        return httpx.Response(200, json={"Logs": [{"Id": "a"}, {"Id": "b"}]})

    with pytest.raises(ZtnaError, match="usable search cursor"):
        ops.audit_logs(connection(handler), 1000, 2000, limit=1)


def test_metric_window_and_read_only_transport_allowlist():
    conn = connection(lambda _: pytest.fail("invalid call reached server"))
    with pytest.raises(ValueError, match="seven days"):
        ops.connector_metrics(conn, "s", 0, 8 * 86400 * 1000, "cpu")
    with pytest.raises(ValueError, match="30 days"):
        ops.audit_logs(conn, 0, 31 * 86400 * 1000)
    with pytest.raises(ValueError, match="read operations"):
        conn._request("DELETE", "/v2/sites/s")


def test_status_and_metrics_shape():
    def handler(request):
        if request.url.path == "/v1/oauth/token":
            return token()
        if request.url.path.endswith("/status"):
            return httpx.Response(200, json={"Status": "online"})
        return httpx.Response(200, json={"resultType": "matrix", "result": []})

    conn = connection(handler)
    assert ops.site_status(conn, "s/1") == {"status": {"Status": "online"}}
    assert ops.connector_metrics(conn, "s1", 1000, 2000, "cpu")["metrics"]["result"] == []
