"""Unified HTTP Interactor - spec §3.2 / §5.

- REST/GraphQL/form requests, Cookie Jar, redirect control.
- Every request passes through ScopeGuard (per-request check).
- Records full request/response for evidence.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from .auth import ScopeGuard


#: RFC 9110 安全方法 — read-only 模式的物理封鎖白名單。
#: OPTIONS 納入:其語意為「詢問可用方法」,不產生副作用(且 ScopeGuard
#: 憑證範疇通常已明示允許);若憑證只准 GET/HEAD,scope 層會再擋一次。
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass
class InteractionRecord:
    method: str
    url: str
    status: int | None
    request_headers: dict | None
    response_headers: dict | None
    body: bytes | None
    ts: float = field(default_factory=time.time)
    blocked_by_scope: bool = False
    blocked_by_readonly: bool = False


class RedTeamHTTP:
    """Scope-enforced HTTP client.

    read_only=True(生產環境保險絲):任何非安全方法(GET/HEAD/OPTIONS 之外)
    在 HTTP 層物理封鎖 — 請求根本不會離網,回傳 blocked_by_readonly 記錄。
    這是防禦深度第二層:即使 playbook/掃描器邏輯宣告 POST,也到不了目標。
    """

    def __init__(self, guard: ScopeGuard | None = None, follow_redirects: bool = False,
                 timeout: float = 30.0, read_only: bool = False):
        self.guard = guard
        self.read_only = read_only
        self.timeout = timeout
        self.client = httpx.Client(follow_redirects=follow_redirects, timeout=timeout)
        # 每次請求附加的預設標頭(如 Authorization):供帶鑰端點探測用。
        # 由 CLI --auth-header 注入;值只存在於記憶體,絕不寫入報告/日誌。
        self.default_headers: dict[str, str] = {}
        self.cookies = {}
        self.records: list[InteractionRecord] = []
        # QPS throttle
        self._last_req = 0.0
        self.min_interval = 0.1  # default 10 QPS

    def set_rate(self, qps: float) -> None:
        self.min_interval = 1.0 / max(qps, 0.1)

    def _throttle(self) -> None:
        elapsed = time.time() - self._last_req
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_req = time.time()

    def _split(self, url: str) -> tuple[str, int, str]:
        u = urlparse(url)
        port = u.port or (443 if u.scheme == "https" else 80)
        return u.hostname or "", port, u.path or "/"

    def request(self, method: str, url: str, *, params=None, json=None, data=None, headers=None) -> InteractionRecord:
        # Scope check — blocked requests RETURN a blocked record (no exception),
        # so callers can distinguish "blocked by scope" from a hard error
        # (LLMTarget.chat / cli rely on rec.blocked_by_scope).
        # read-only hard block — enforced BEFORE scope and BEFORE the wire.
        # A blocked record is returned (no exception) so callers can render it.
        if self.read_only and method.upper() not in SAFE_METHODS:
            rec = InteractionRecord(method, url, None, None, None, None,
                                    blocked_by_readonly=True)
            self.records.append(rec)
            return rec

        host, port, path = self._split(url)
        if self.guard:
            if not self.guard.check(host, port, path, method):
                rec = InteractionRecord(method, url, None, None, None, None, blocked_by_scope=True)
                self.records.append(rec)
                return rec

        self._throttle()
        # 合併預設標頭(呼叫端顯式標頭優先);--auth-header 由此注入
        merged = {**self.default_headers, **(headers or {})}
        resp = self.client.request(method, url, params=params, json=json, data=data, headers=merged)
        # 憑證鐵律:Authorization/Cookie 的密鑰值不進證據鏈 —
        # 記錄前就地脫敏(報告層 redact() 是第二道,這裡不依賴它)。
        req_headers = dict(resp.request.headers)
        for h in ("authorization", "cookie", "proxy-authorization"):
            if h in req_headers:
                req_headers[h] = "[REDACTED]"
        rec = InteractionRecord(
            method, str(resp.url), resp.status_code, req_headers,
            dict(resp.headers), resp.content,
        )
        self.records.append(rec)
        return rec


class AuthError(PermissionError):
    pass
