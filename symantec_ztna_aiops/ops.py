"""Documented read-only Symantec ZTNA tenant operations."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from symantec_ztna_aiops.connection import ZtnaConnection, ZtnaError


def _id(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("A non-empty ZTNA resource ID is required")
    return quote(value, safe="")


def _limit(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100:
        raise ValueError("limit must be between 1 and 100")
    return value


def _page_number(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("page must be zero or greater")
    return value


def _paged(
    conn: ZtnaConnection, path: str, *, limit: int = 50, page: int = 0, filter_text: str = ""
) -> dict:
    limit, page = _limit(limit), _page_number(page)
    if len(filter_text) > 200:
        raise ValueError("filter_text must be at most 200 characters")
    params: dict[str, Any] = {"size": limit, "page": page}
    if filter_text:
        params["filter"] = filter_text
    data = conn.get(path, params=params)
    if not isinstance(data, dict) or not isinstance(data.get("content"), list):
        raise ZtnaError(f"ZTNA returned an unexpected page for {path}")
    items = data["content"]
    if any(not isinstance(item, dict) for item in items) or len(items) > limit:
        raise ZtnaError(f"ZTNA returned invalid page items for {path}")
    if data.get("number") != page or not isinstance(data.get("last"), bool):
        raise ZtnaError(f"ZTNA returned invalid page metadata for {path}")
    total = data.get("totalElements")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        raise ZtnaError(f"ZTNA returned invalid totalElements for {path}")
    if not data["last"] and not items:
        raise ZtnaError(f"ZTNA returned an empty non-final page for {path}")
    return {
        "items": items,
        "returned": len(items),
        "limit": limit,
        "page": page,
        "truncated": not data["last"],
        "nextPage": page + 1 if not data["last"] else None,
        "totalReported": total,
    }


def _detail(conn: ZtnaConnection, path: str, key: str) -> dict:
    data = conn.get(path)
    if not isinstance(data, dict) or not data:
        raise ZtnaError(f"ZTNA returned an unexpected {key} response")
    return {key: data}


def _array(conn: ZtnaConnection, path: str, *, limit: int = 100) -> dict:
    limit = _limit(limit)
    data = conn.get(path)
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise ZtnaError(f"ZTNA returned an unexpected list for {path}")
    return {
        "items": data[:limit],
        "returned": min(len(data), limit),
        "limit": limit,
        "truncated": len(data) > limit,
    }


def sites(conn: ZtnaConnection, limit: int = 50, page: int = 0, filter_text: str = "") -> dict:
    return _paged(conn, "/v2/sites", limit=limit, page=page, filter_text=filter_text)


def site(conn: ZtnaConnection, site_id: str) -> dict:
    return _detail(conn, f"/v2/sites/{_id(site_id)}", "site")


def site_status(conn: ZtnaConnection, site_id: str) -> dict:
    return _detail(conn, f"/v2/sites/{_id(site_id)}/status", "status")


def regions(conn: ZtnaConnection, limit: int = 100) -> dict:
    return _array(conn, "/v2/regions", limit=limit)


def connectors(conn: ZtnaConnection, limit: int = 50, page: int = 0, filter_text: str = "") -> dict:
    return _paged(conn, "/v2/connectors", limit=limit, page=page, filter_text=filter_text)


def connector(conn: ZtnaConnection, connector_id: str) -> dict:
    return _detail(conn, f"/v2/connectors/{_id(connector_id)}", "connector")


def connector_version(conn: ZtnaConnection) -> dict:
    return _detail(conn, "/v2/connectors/version", "version")


def applications(
    conn: ZtnaConnection, limit: int = 50, page: int = 0, filter_text: str = ""
) -> dict:
    return _paged(conn, "/v2/applications", limit=limit, page=page, filter_text=filter_text)


def application(conn: ZtnaConnection, application_id: str) -> dict:
    return _detail(conn, f"/v2/applications/{_id(application_id)}", "application")


def application_status(conn: ZtnaConnection, application_id: str) -> dict:
    return _detail(conn, f"/v2/applications/{_id(application_id)}/status", "status")


def policies(conn: ZtnaConnection, limit: int = 50, page: int = 0, filter_text: str = "") -> dict:
    return _paged(conn, "/v2/policies", limit=limit, page=page, filter_text=filter_text)


def policy(conn: ZtnaConnection, policy_id: str) -> dict:
    return _detail(conn, f"/v2/policies/{_id(policy_id)}", "policy")


def application_policies(conn: ZtnaConnection, application_id: str, limit: int = 100) -> dict:
    return _array(conn, f"/v2/policies/by-app-id/{_id(application_id)}", limit=limit)


def connector_metrics(
    conn: ZtnaConnection, site_id: str, start_ms: int, end_ms: int, metric: str, step: int = 300
) -> dict:
    if any(isinstance(v, bool) or not isinstance(v, int) for v in (start_ms, end_ms, step)):
        raise ValueError("start_ms, end_ms and step must be integers")
    if start_ms < 0 or end_ms <= start_ms or end_ms - start_ms > 7 * 86400 * 1000:
        raise ValueError("metrics range must be ascending and at most seven days")
    if not 60 <= step <= 43200 or not metric or len(metric) > 50:
        raise ValueError("metric is required and step must be 60–43200 seconds")
    data = conn.get(
        f"/v2/observability/sites/{_id(site_id)}/connector-utilization",
        params={"start": start_ms, "end": end_ms, "metric": metric, "step": step},
    )
    if not isinstance(data, dict) or not isinstance(data.get("result"), list):
        raise ZtnaError("ZTNA returned unexpected connector metrics")
    return {"metrics": data}


def audit_logs(
    conn: ZtnaConnection,
    start_ms: int,
    end_ms: int,
    limit: int = 100,
    free_text: str = "",
    cursor_time: int | None = None,
    cursor_id: str | None = None,
) -> dict:
    limit = _limit(limit)
    if any(isinstance(v, bool) or not isinstance(v, int) for v in (start_ms, end_ms)):
        raise ValueError("start_ms and end_ms must be integer epoch milliseconds")
    if start_ms < 0 or end_ms <= start_ms or end_ms - start_ms > 30 * 86400 * 1000:
        raise ValueError("audit range must be ascending and at most 30 days")
    if len(free_text) > 200:
        raise ValueError("free_text must be at most 200 characters")
    if (cursor_time is None) != (cursor_id is None):
        raise ValueError("cursor_time and cursor_id must be supplied together")
    payload: dict[str, Any] = {
        "size": limit + 1,
        "query": {"from_date": start_ms, "to_date": end_ms},
    }
    if free_text:
        payload["query"]["free_text"] = free_text
    if cursor_time is not None:
        if isinstance(cursor_time, bool) or not isinstance(cursor_time, int) or not cursor_id:
            raise ValueError("invalid audit cursor")
        payload["search_after"] = [cursor_time, cursor_id]
    data = conn.search_audit(payload)
    if not isinstance(data, dict) or not isinstance(data.get("Logs"), list):
        raise ZtnaError("ZTNA returned unexpected audit search results")
    rows = data["Logs"]
    if any(not isinstance(row, dict) for row in rows) or len(rows) > limit + 1:
        raise ZtnaError("ZTNA returned invalid audit rows")
    truncated = len(rows) > limit
    items = rows[:limit]
    cursor = items[-1].get("SearchAfterValues") if truncated and items else None
    if truncated and (
        not isinstance(cursor, list)
        or len(cursor) != 2
        or isinstance(cursor[0], bool)
        or not isinstance(cursor[0], int)
        or not isinstance(cursor[1], str)
    ):
        raise ZtnaError("ZTNA audit response omitted a usable search cursor")
    return {
        "items": items,
        "returned": len(items),
        "limit": limit,
        "truncated": truncated,
        "nextCursor": cursor,
    }


def health_sample(conn: ZtnaConnection, limit: int = 20) -> dict:
    probes = {"sites": sites, "connectors": connectors, "applications": applications}
    sample: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for name, probe in probes.items():
        try:
            sample[name] = probe(conn, limit)
        except ZtnaError as exc:
            sample[name] = None
            errors[name] = str(exc)
    return {"sample": sample, "errors": errors, "partial": bool(errors), "sampleLimit": limit}
