"""Tenant-scoped ZTNA OAuth transport with bounded authentication retries."""

from __future__ import annotations

import os
import threading
import time
from typing import Any
from urllib.parse import urlsplit

import httpx


class ZtnaError(RuntimeError):
    """Actionable API error without token or response-body disclosure."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _settings() -> tuple[str, str, str, float, bool | str]:
    url = os.environ.get("SYMANTEC_ZTNA_URL", "").rstrip("/")
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or not parts.netloc
        or parts.path
        or parts.query
        or parts.fragment
        or parts.username
        or parts.password
    ):
        raise ZtnaError("Set SYMANTEC_ZTNA_URL to the tenant API HTTPS origin")
    client_id = os.environ.get("SYMANTEC_ZTNA_CLIENT_ID", "")
    client_secret = os.environ.get("SYMANTEC_ZTNA_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        raise ZtnaError("Set SYMANTEC_ZTNA_CLIENT_ID and SYMANTEC_ZTNA_CLIENT_SECRET")
    try:
        timeout = float(os.environ.get("SYMANTEC_ZTNA_TIMEOUT", "30"))
    except ValueError as exc:
        raise ZtnaError("SYMANTEC_ZTNA_TIMEOUT must be positive") from exc
    if timeout <= 0:
        raise ZtnaError("SYMANTEC_ZTNA_TIMEOUT must be positive")
    return url, client_id, client_secret, timeout, os.environ.get("SYMANTEC_ZTNA_CA_BUNDLE") or True


class ZtnaConnection:
    def __init__(self, client: httpx.Client | None = None) -> None:
        url, self._client_id, self._client_secret, timeout, verify = _settings()
        self._client = client or httpx.Client(base_url=url, timeout=timeout, verify=verify)
        self._token: str | None = None
        self._expires_at = 0.0
        self._auth_retry_at = 0.0
        self._lock = threading.RLock()

    def close(self) -> None:
        self._client.close()

    def _authenticate(self) -> None:
        if time.monotonic() < self._auth_retry_at:
            raise ZtnaError("ZTNA login was rejected recently; wait before retrying credentials")
        try:
            response = self._client.post(
                "/v1/oauth/token",
                auth=(self._client_id, self._client_secret),
                headers={"Accept": "application/json"},
            )
        except httpx.TimeoutException as exc:
            raise ZtnaError("ZTNA login timed out; check tenant URL and timeout") from exc
        except httpx.HTTPError as exc:
            raise ZtnaError("Cannot reach ZTNA login; check tenant URL and TLS") from exc
        if response.status_code in (400, 401, 403):
            self._auth_retry_at = time.monotonic() + 30
            raise ZtnaError("ZTNA rejected OAuth credentials or client privileges")
        if response.status_code >= 400:
            raise ZtnaError(f"ZTNA login returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise ZtnaError("ZTNA login returned non-JSON data") from exc
        token = data.get("access_token") if isinstance(data, dict) else None
        raw_expiry = data.get("expires_in") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise ZtnaError("ZTNA login response has no access_token")
        if isinstance(raw_expiry, bool) or not isinstance(raw_expiry, (int, str)):
            raise ZtnaError("ZTNA login response has invalid expires_in")
        try:
            expiry = int(raw_expiry)
        except ValueError as exc:
            raise ZtnaError("ZTNA login response has invalid expires_in") from exc
        if expiry <= 0:
            raise ZtnaError("ZTNA login response has invalid expires_in")
        self._token = token
        self._expires_at = time.monotonic() + max(1, expiry - 60)
        self._auth_retry_at = 0.0

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        if not path.startswith("/v2/") or path.startswith("//"):
            raise ValueError("ZTNA resource path must start with /v2/")
        if method != "GET" and (method != "POST" or path != "/v2/logs/audit"):
            raise ValueError("ZTNA transport only exposes documented read operations")
        with self._lock:
            if self._token is None or time.monotonic() >= self._expires_at:
                self._authenticate()
            for attempt in range(2):
                try:
                    response = self._client.request(
                        method,
                        path,
                        params=params,
                        json=payload,
                        headers={
                            "Authorization": f"Bearer {self._token}",
                            "Accept": "application/json",
                        },
                    )
                except httpx.TimeoutException as exc:
                    raise ZtnaError(
                        f"ZTNA timed out on {path}; check SYMANTEC_ZTNA_TIMEOUT"
                    ) from exc
                except httpx.HTTPError as exc:
                    raise ZtnaError(
                        f"Cannot reach ZTNA on {path}; check tenant URL and TLS"
                    ) from exc
                if response.status_code == 401 and attempt == 0:
                    self._token = None
                    self._authenticate()
                    continue
                if response.status_code >= 400:
                    hint = "Check client role and resource ID."
                    if response.status_code == 429:
                        hint = "ZTNA quota exceeded; retry after the server's limit resets."
                    elif response.status_code >= 500:
                        hint = "Check ZTNA service health before retrying."
                    raise ZtnaError(
                        f"ZTNA returned HTTP {response.status_code} for {path}. {hint}",
                        status_code=response.status_code,
                    )
                if not response.content:
                    raise ZtnaError(f"ZTNA returned an empty response for {path}")
                try:
                    return response.json()
                except ValueError as exc:
                    raise ZtnaError(f"ZTNA returned non-JSON data for {path}") from exc
            raise ZtnaError("ZTNA authentication retry failed")

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        return self._request("GET", path, params=params)

    def search_audit(self, payload: dict[str, Any]) -> Any:
        return self._request("POST", "/v2/logs/audit", payload=payload)


_connection: ZtnaConnection | None = None
_connection_lock = threading.Lock()


def get_connection() -> ZtnaConnection:
    global _connection
    with _connection_lock:
        if _connection is None:
            _connection = ZtnaConnection()
        return _connection
