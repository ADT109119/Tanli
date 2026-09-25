"""軟體版本 CVE 比對器(version watch)— 實務需求產品化。

動機:指紋拿到框架版本(如 n8n@2.39.4)後,官方可能兩天前才剛發安全公告
(修復版 2.39.6),全靠手動查論壇太慢。
本模組把「指紋 → 版本 → GHSA 查詢 → 適用 CVE + 修復版本」自動化。

資料源:GitHub Advisory Database (GHSA) REST API — 公開、免驗證可用
(匿名限 60 req/h;設 GITHUB_TOKEN 升到 5000)。
GHSA 的 vulnerable_version_range/first_patched_version 直接給「修復版」,
比 NVD 的 CPE 匹配乾淨得多(opensource-gateway review 共識)。

鐵律:
- 所有 HTTP 一律經 RedTeamHTTP(ScopeGuard 不可繞過;GHSA 查詢走
  api.github.com 屬「非靶點」控制平面流量,故用獨立無 guard client —
  與 llm judge 同級,僅讀公開 API,不對靶點產生流量)。
- 嚴禁任何寫操作：全程 GET only。
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

GHSA_API = "https://api.github.com/advisories"


# ---------------------------------------------------------------------------
# 語義化版本比較(不做完整 semver,只覆蓋 GHSA range 需要的 <, <= 語意)
# ---------------------------------------------------------------------------

def parse_version(v: str) -> tuple:
    """'2.39.4' -> (2,39,4);非數字段退到 int 前綴('1.0.0-rc1'->(1,0,0))。"""
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums[:4]) or (0,)


def version_lt(a: str, b: str) -> bool:
    """a < b(逐段整數比較,短者補 0)。"""
    pa, pb = parse_version(a), parse_version(b)
    n = max(len(pa), len(pb))
    pa += (0,) * (n - len(pa))
    pb += (0,) * (n - len(pb))
    return pa < pb


def version_in_range(current: str, vulnerable_range: str) -> bool:
    """判斷 current 是否落在 GHSA 的 vulnerable_version_range 內。

    支援 GHSA 常見語法:"< 2.5.2"、">= 2.0.0, < 2.10.0"、"*"(全中)。
    無法解析的 range 一律回 False(寧可漏報不誤報 — 報告會標註來源可查)。
    """
    if not vulnerable_range or vulnerable_range.strip() in ("*", "< 0"):
        return True
    for clause in vulnerable_range.split(","):
        c = clause.strip()
        m = re.match(r"^(<=?|>=?|=|!=)?\s*([\w.\-+]+)$", c)
        if not m:
            return False  # 不認識的語法 → 保守跳過
        op, ver = m.group(1) or "=", m.group(2)
        if op == "<" and not version_lt(current, ver):
            return False
        if op == "<=" and parse_version(current) > parse_version(ver):
            return False
        if op == ">" and not version_lt(ver, current):
            return False
        if op == ">=" and parse_version(current) < parse_version(ver):
            return False
        if op == "=" and parse_version(current) != parse_version(ver):
            return False
        if op == "!=" and parse_version(current) == parse_version(ver):
            return False
    return True


# ---------------------------------------------------------------------------
# GHSA 查詢
# ---------------------------------------------------------------------------

@dataclass
class CveMatch:
    cve: str
    ghsa: str
    summary: str
    severity: str          # critical | high | moderate | low
    vulnerable_range: str
    first_patched: str | None
    published: str


@dataclass
class VersionWatchResult:
    """一個軟體組件的 CVE 比對結果(與 ProbeResult 語意對齊:
    passed=True 代表「發現適用未修 CVE」= 弱點確認)。"""

    product: str
    ecosystem: str      # npm | pip | pypi | maven | ...
    current_version: str
    matches: list[CveMatch] = field(default_factory=list)
    error: str = ""
    latest_advisory_date: str = ""  # 資料源最新公告日(新鮮度誠實標示)

    @property
    def passed(self) -> bool:
        return bool(self.matches)

    @property
    def blocked_by_scope(self) -> bool:
        return False

    @property
    def highest_severity(self) -> str:
        order = ["critical", "high", "moderate", "medium", "low"]
        for s in order:
            if any(m.severity == s for m in self.matches):
                return {"moderate": "medium"}.get(s, s)
        return "low" if self.matches else "info"


def query_ghsa(product: str, ecosystem: str, token: str | None = None,
               timeout: float = 20.0, page_size: int = 100) -> list[dict]:
    """查 GHSA 該 package 的全部公告(GET only)。異常向上拋,呼叫端降級。

    實錄教訓(2026-09-25 www.tph run):
    - product 含空格("Apache HTTP Server")未 encode 直接進 URL →
      InvalidURL 崩潰,故參數一律 quote。
    - ecosystem 非 GHSA 合法值(GHSA 只認 npm/pip/maven/...)→ 422,
      轉成可操作中文訊息,讓 agent 知道該改走 NVD。
    """
    qs = urllib.parse.urlencode({"ecosystem": ecosystem, "affects": product,
                                 "per_page": page_size}, quote_via=urllib.parse.quote)
    url = f"{GHSA_API}?{qs}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "tanli-version-watch",
    })
    tok = token or os.environ.get("GITHUB_TOKEN", "")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 422:
            raise ValueError(
                f"GHSA 422:ecosystem={ecosystem!r} 或 product={product!r} 不是"
                " GHSA 合法組合(伺服器軟體如 Apache/nginx/IIS 不在套件生態系,"
                "應改用 cve_lookup 的 NVD 關鍵字查詢)") from e
        raise


#: GHSA ecosystem 正名(pypi 慣用寫法 -> GHSA 的 pip)
ECOSYSTEM_ALIAS = {"pypi": "pip", "pypi.org": "pip", "nuget": "nuget", "packagist": "packagist"}


def watch(product: str, ecosystem: str, current_version: str,
          token: str | None = None) -> VersionWatchResult:
    """比對 current_version 受哪些已發布 CVE 影響,附修復版本。"""
    ecosystem = ECOSYSTEM_ALIAS.get(ecosystem.lower(), ecosystem.lower())
    res = VersionWatchResult(product=product, ecosystem=ecosystem,
                             current_version=current_version)
    try:
        advisories = query_ghsa(product, ecosystem, token=token)
    except Exception as e:  # noqa: BLE001
        res.error = f"GHSA 查詢失敗({e.__class__.__name__}): {e}"
        return res
    # 資料源新鮮度:GHSA 對廠商公告有數天同步滯後(實測案例:9/16 公告
    # 於 9/18 仍未入庫)。matches=0 時報告必須標出最新公告日,
    # 避免「查無 CVE」被誤讀成「真的沒漏洞」。
    dates = [str(a.get("published_at") or "")[:10] for a in advisories if a.get("published_at")]
    res.latest_advisory_date = max(dates) if dates else ""
    for a in advisories:
        for v in a.get("vulnerabilities", []):
            pkg = v.get("package", {})
            if pkg.get("name") != product or pkg.get("ecosystem") != ecosystem:
                continue
            rng = v.get("vulnerable_version_range") or ""
            if not version_in_range(current_version, rng):
                continue
            res.matches.append(CveMatch(
                cve=a.get("cve_id") or a.get("ghsa_id") or "?",
                ghsa=a.get("ghsa_id") or "?",
                summary=(a.get("summary") or "")[:200],
                severity=a.get("severity") or "unknown",
                vulnerable_range=rng,
                first_patched=v.get("first_patched_version"),
                published=(a.get("published_at") or "")[:10],
            ))
            break  # 同一 advisory 同一 package 只取一個 range 命中
    return res


# ---------------------------------------------------------------------------
# 指紋自動偵測:從 HTML/JS 中找 <pkg>@<ver> 宣告(常見於 sentry release meta
# — "release":"pkg@2.39.4")。回傳候選清單 [(product, version)]。
# ---------------------------------------------------------------------------

#: sentry 常見 release 宣告:"release":"n8n@2.39.4" / release=n8n@2.39.4
_RELEASE_DECL = re.compile(r"""release["']?\s*[:=]\s*["']?([\w.\-]+)@(\d[\w.\-]*)""")

#: HTML 屬性中的 base64 值(實測案例:release 藏在 base64 meta 後)
_B64_ATTR = re.compile(r"""["']([A-Za-z0-9+/]{24,}={0,2})["']""")


def _b64_candidates(html: str) -> list[str]:
    """把 HTML 中疑似 base64 的屬性值解碼成文字片段(解不出就跳過)。"""
    import base64
    out = []
    for m in _B64_ATTR.finditer(html or ""):
        raw = m.group(1)
        try:
            dec = base64.b64decode(raw + "==", validate=False).decode("utf-8", "strict")
        except Exception:
            continue
        if "release" in dec:
            out.append(dec)
    return out


def detect_releases(body_text: str, limit: int = 5) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    # 明文 + base64 解碼後都要掃(n8n 的 release 藏在 base64 meta 內)
    haystacks = [body_text or ""] + _b64_candidates(body_text or "")
    for hay in haystacks:
        for m in _RELEASE_DECL.finditer(hay):
            name, ver = m.group(1).lower(), m.group(2)
            if name not in seen:
                seen.add(name)
                out.append((name, ver))
            if len(out) >= limit:
                return out
    return out
