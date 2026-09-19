"""web_config 確定性探測器 - M5.

針對目標站點的 HTTP 安全組態做「純規則」探測(無 LLM、無 Docker):
- 缺失安全回應標頭:Content-Security-Policy、Strict-Transport-Security
  (僅 https 目標檢查;http 目標跳過並記錄原因)、X-Frame-Options、
  X-Content-Type-Options、Referrer-Policy
- Cookie 屬性:Set-Cookie 有值但缺 HttpOnly / 缺 Secure

鐵律:所有請求一律經 RedTeamHTTP 發出(ScopeGuard 不可被繞過);
結果結構與 LLM playbook 的 ProbeResult 概念對齊(passed/evidence/steps)。
本探測器為純確定性規則,不需要 LLM judge 二次確認。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from .auth import ScopeGuard
from .interactor import RedTeamHTTP

#: 預設探測路徑(本里程碑只探 "/")
DEFAULT_PATHS: list[str] = ["/"]

# OWASP 對應說明:安全頭缺失與弱 cookie 屬性本質上都是「預設組態不安全」,
# 統一映射到 OWASP 2021 A05 Security Misconfiguration。
# (HSTS 涉及傳輸層保護,亦可論 A02 Cryptographic Failures;但業界掃描器
#  慣例多歸 A05,此處從眾,便於報告聚合。)
OWASP_A05 = "A05"

#: 必檢安全回應標頭(小寫)-> 預設嚴重度
#: - CSP 缺失 → medium(XSS 緩解主防線)
#: - HSTS 缺失 → low(僅 https);XFO/XCTO/Referrer-Policy → low
REQUIRED_HEADERS: list[tuple[str, str]] = [
    ("content-security-policy", "medium"),
    ("strict-transport-security", "low"),
    ("x-frame-options", "low"),
    ("x-content-type-options", "low"),
    ("referrer-policy", "low"),
]

#: 進 evidence 摘要的標頭(小寫;依序取值做 header dump)
_SUMMARY_KEYS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "set-cookie",
    "server",
    "content-type",
)

#: Expires/Last-Modified 型日期殘段(如 ", 21 Oct 2026 ..."),逗號不可當 cookie 分隔
_DATE_CONTINUATION = re.compile(r"^\s*\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)", re.IGNORECASE)
#: 前一段尾端停在 Expires= 後且緊接星期簡寫(如 "Expires=Wed")
#: 時,下一個逗號段是日期續體("21 Oct 2026 ...")。
#: 注意:Domain=/Max-Age= 的值絕不含逗號,不可納入此判定 ——
#: 否則 "a=1; Domain=example.com, b=2" 會把 b 誤併入 a 造成漏報 (agy Finding-01)。
_EXPIRES_TAIL = re.compile(r"expires\s*=\s*[a-z]{3}\s*$", re.IGNORECASE)
#: 新 cookie 片段的開頭(token= 形式)
_COOKIE_START = re.compile(r"^\s*[^\s;,=]+=")


@dataclass
class WebConfigProbeResult:
    """單一檢查項的結果(與 playbook.ProbeResult 概念對齊)。

    passed=True 代表「弱點確認」(缺頭 / 弱 cookie 屬性);
    blocked_by_scope=True 代表請求被 ScopeGuard 攔截(必為 passed=False)。
    """

    id: str
    name: str
    path: str
    category: str  # security_header | cookie_attr
    severity: str  # critical | high | medium | low | info
    owasp: str     # 本里程碑統一 A05(見上方註解)
    passed: bool
    blocked_by_scope: bool = False
    steps: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


class WebConfigProbe:
    """以既有 RedTeamHTTP(ScopeGuard 在位)執行確定性 web 組態探測。"""

    def __init__(self, http: RedTeamHTTP | None = None):
        # 未提供 client 時自建 localhost-only guard 的 client —— 探測永不繞過 ScopeGuard
        self.http = http or RedTeamHTTP(guard=ScopeGuard(None))

    def run(self, base_url: str, paths: list[str] | None = None) -> list[WebConfigProbeResult]:
        """對 base_url 的每個 path 發 GET,逐項產生檢查結果。

        回傳清單包含「全部檢查項」(含未中靶的 passed=False 項與
        http 目標跳過 HSTS 的說明項),呼叫端以 passed 過濾出 finding。
        """
        paths = paths or DEFAULT_PATHS
        scheme = (urlparse(base_url).scheme or "http").lower()
        is_https = scheme == "https"
        results: list[WebConfigProbeResult] = []
        for p in paths:
            url = base_url.rstrip("/") + (p if p.startswith("/") else f"/{p}")
            try:
                rec = self.http.request("GET", url)
            except httpx.HTTPError as e:
                # 連線失敗/逾時:不可讓單一 path 的中斷炸掉整次 run,
                # 也不可用「空 headers」誤報全數標頭缺失 (agy Finding-03)。
                results.append(
                    WebConfigProbeResult(
                        id=f"webconfig-err({p})",
                        name=f"探測失敗:連線錯誤 ({e.__class__.__name__})",
                        path=p,
                        category="security_header",
                        severity="info",
                        owasp=OWASP_A05,
                        passed=False,
                        steps=[f"GET {p}"],
                        evidence=[f"url={url}", f"error:{e}"],
                    )
                )
                continue
            if rec.blocked_by_scope:
                results.append(
                    WebConfigProbeResult(
                        id=f"webconfig-blocked({p})",
                        name="請求被 ScopeGuard 攔截",
                        path=p,
                        category="security_header",
                        severity="info",
                        owasp=OWASP_A05,
                        passed=False,
                        blocked_by_scope=True,
                        steps=[f"GET {p}"],
                        evidence=[f"url={url}(超出授權範圍)"],
                    )
                )
                continue
            # httpx 標頭鍵一律小寫;再保險轉一次小寫以防其他來源大小寫不一
            headers = {k.lower(): v for k, v in (rec.response_headers or {}).items()}
            summary = self._header_summary(headers)
            if rec.status is not None and rec.status >= 500:
                # 5xx:回應是伺服器錯誤頁而非目標的正常組態;對錯誤頁判
                # 「缺少安全標頭」會誤報 (agy Finding-03),改記 info 並跳過。
                results.append(
                    WebConfigProbeResult(
                        id=f"webconfig-5xx({p})",
                        name=f"目標回傳伺服器錯誤 ({rec.status}),略過組態檢查",
                        path=p,
                        category="security_header",
                        severity="info",
                        owasp=OWASP_A05,
                        passed=False,
                        steps=[f"GET {p}"],
                        evidence=[f"status:{rec.status}", summary],
                    )
                )
                continue
            results += self._check_headers(p, headers, summary, is_https)
            results += self._check_cookies(p, headers, summary, is_https)
        return results

    # ------------------------------------------------------------------
    # 檢查項一:缺失安全回應標頭
    # ------------------------------------------------------------------
    def _check_headers(
        self, path: str, headers: dict[str, str], summary: str, is_https: bool
    ) -> list[WebConfigProbeResult]:
        out: list[WebConfigProbeResult] = []
        for idx, (name, sev) in enumerate(REQUIRED_HEADERS, 1):
            pid = f"webconfig-h{idx}-{name}"
            if name == "strict-transport-security" and not is_https:
                # HSTS 僅對 https 目標有意義:http 目標跳過並記 reason(passed=False)
                out.append(
                    WebConfigProbeResult(
                        id=pid,
                        name="HSTS 檢查略過(http 目標)",
                        path=path,
                        category="security_header",
                        severity="info",
                        owasp=OWASP_A05,
                        passed=False,
                        steps=[f"GET {path}"],
                        evidence=[summary, "reason:HSTS 僅適用於 https 目標,http 不予檢查"],
                    )
                )
                continue
            present = bool(headers.get(name, "").strip())
            out.append(
                WebConfigProbeResult(
                    id=pid,
                    name=f"缺少安全回應標頭 {name}" if not present else f"{name} 已設定",
                    path=path,
                    category="security_header",
                    severity=sev if not present else "info",
                    owasp=OWASP_A05,
                    passed=not present,
                    steps=[f"GET {path}"],
                    evidence=[summary],
                )
            )
        return out

    # ------------------------------------------------------------------
    # 檢查項二:Set-Cookie 屬性(HttpOnly / Secure)
    # ------------------------------------------------------------------
    def _check_cookies(
        self, path: str, headers: dict[str, str], summary: str, is_https: bool
    ) -> list[WebConfigProbeResult]:
        raw = headers.get("set-cookie", "")
        if not raw.strip():
            return []  # 無 Set-Cookie → 不檢查,避免誤報
        out: list[WebConfigProbeResult] = []
        for i, ck in enumerate(self._split_cookies(raw), 1):
            name = ck.split("=", 1)[0].strip() or f"cookie{i}"
            flags = [f.strip().lower() for f in ck.split(";")[1:]]
            # HttpOnly / Secure 為布林屬性(無等號、無值),必須「整詞精準比對」:
            # startswith 會被自訂屬性誤判(如 "SecureProxy=true" 會偽陽性)
            # 造成漏報 (agy Finding-02)。
            has_httponly = any(f == "httponly" for f in flags)
            has_secure = any(f == "secure" for f in flags)
            ev = [f"set-cookie:{ck[:200]}", summary]
            if not has_httponly:
                out.append(
                    WebConfigProbeResult(
                        id=f"webconfig-c{i}-httponly-{name}",
                        name=f"Cookie '{name}' 缺少 HttpOnly",
                        path=path,
                        category="cookie_attr",
                        severity="low",
                        owasp=OWASP_A05,
                        passed=True,
                        steps=[f"GET {path}"],
                        evidence=ev,
                    )
                )
            if not has_secure:
                # http 目標:Secure 在明文通道上本就無法生效,只記 info 避免
                # 製造 medium 噪音;https 目標才視為 low 弱點。
                out.append(
                    WebConfigProbeResult(
                        id=f"webconfig-c{i}-secure-{name}",
                        name=f"Cookie '{name}' 缺少 Secure",
                        path=path,
                        category="cookie_attr",
                        severity="low" if is_https else "info",
                        owasp=OWASP_A05,
                        passed=True,
                        steps=[f"GET {path}"],
                        evidence=ev,
                    )
                )
        return out

    @staticmethod
    def _split_cookies(raw: str) -> list[str]:
        """把 Set-Cookie 字串切成單一 cookie 清單。

        httpx 將多個同名 Set-Cookie 以 ', ' 合併成單一值;此處用啟發式切分:
        在逗號處切開,但「Expires 型日期殘段」(如 'Wed, 21 Oct 2026 ...')
        或前段尾端停在 Expires=/Domain=/Max-Age= 之後時不合併也不切分。
        本里程碑靶場僅送單一 cookie;此函式主要為真實世界多 cookie 情境保留。
        """
        out: list[str] = []
        cur = ""
        for seg in raw.split(","):
            if not cur:
                cur = seg
            elif _DATE_CONTINUATION.match(seg) or _EXPIRES_TAIL.search(cur):
                cur += "," + seg  # 日期續體,不是新的 cookie
            elif _COOKIE_START.match(seg):
                out.append(cur.strip())
                cur = seg
            else:
                cur += "," + seg
        if cur.strip():
            out.append(cur.strip())
        return out

    @staticmethod
    def _header_summary(headers: dict[str, str]) -> str:
        """實際回應標頭的摘要 dump(進 evidence,供報告與人工複核)。"""
        parts = [
            f"{k}:{headers[k][:120]}" for k in _SUMMARY_KEYS if k in headers
        ]
        return " | ".join(parts) if parts else "(無相關標頭)"
