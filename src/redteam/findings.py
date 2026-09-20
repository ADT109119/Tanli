"""Scanner result -> Finding converter - spec §6.

Normalizes nuclei/sqlmap/ZAP output into the report's Finding schema
with CVSS-ish severity mapping and evidence for the LLM judge.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# nuclei severity -> report severity
NUCLEI_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}

# ZAP alert-id prefix hints (heuristic category guess; judge can refine)
ZAP_CATEGORY_HINT = {
    "10020": "security_header",  # anti-clickjacking
    "10021": "security_header",
    "10035": "security_header",
    "10036": "info_disclosure",
    "10038": "security_header",
    "10049": "cache_policy",
    "10063": "security_header",
    "90004": "security_header",
}

# ---------------------------------------------------------------------------
# P1: OWASP 2021 category mapping (A01-A10) - spec §B W-01~W-06 alignment
# ---------------------------------------------------------------------------

#: OWASP 2021 Top 10 readable names (for report aggregation labels)
OWASP_NAMES = {
    "A01": "訪問控制損壞",
    "A02": "加密失敗",
    "A03": "注入",
    "A04": "不安全設計",
    "A05": "安全配置錯誤",
    "A06": "易受攻擊與過時元件",
    "A07": "認證與驗證失敗",
    "A08": "軟體與資料完整性失敗",
    "A09": "日誌與監控失敗",
    "A10": "伺服器端請求偽造 (SSRF)",
}

#: nuclei template tags -> OWASP 2021 class (tags take priority over keywords)
NUCLEI_TAG_TO_OWASP = {
    # A01 - 訪問控制
    "idor": "A01", "broken-access-control": "A01", "access-control": "A01",
    "authorization": "A01", "mass-assignment": "A01",
    # A02 - 加密失敗
    "tls": "A02", "ssl": "A02", "weak-crypto": "A02", "weak-tls": "A02",
    "jwt-secret": "A02", "crypto": "A02",
    # A03 - 注入
    "sqli": "A03", "sql-injection": "A03", "xss": "A03", "rce": "A03",
    "command-injection": "A03", "cmd-injection": "A03", "lfi": "A03",
    "path-traversal": "A03", "ssti": "A03", "xxe": "A03", "injection": "A03",
    "ldap-injection": "A03", "crlf-injection": "A03", "injection-attack": "A03",
    # A05 - 安全配置錯誤
    "misconfig": "A05", "misconfiguration": "A05", "security-misconfiguration": "A05",
    "exposed-panel": "A05", "exposure": "A05", "exposed": "A05", "cors": "A05",
    "cache": "A05", "default-config": "A05",
    "headers": "A05", "security-headers": "A05",
    # A06 - 易受攻擊元件
    "cve": "A06", "known-vuln": "A06",
    # A07 - 認證失敗
    "default-login": "A07", "weak-login": "A07", "broken-auth": "A07",
    "jwt": "A07", "session": "A07", "login": "A07", "cookie": "A07",
    # A10 - SSRF
    "ssrf": "A10", "server-side-request-forgery": "A10",
}

#: fallback keyword map for nuclei template NAMES when no tags present
NUCLEI_KEYWORD_TO_OWASP = {
    "sql injection": "A03", "sqli": "A03", "xss": "A03", "cross-site scripting": "A03",
    "rce": "A03", "remote code": "A03", "command injection": "A03", "lfi": "A03",
    "local file": "A03", "path traversal": "A03", "ssti": "A03", "template injection": "A03",
    "xxe": "A03", "xml external": "A03",
    "idor": "A01", "broken access": "A01", "access control": "A01", "privilege escal": "A01",
    "mass assignment": "A01",
    "tls": "A02", "ssl": "A02", "weak cipher": "A02", "crypto": "A02", "jwt": "A07",
    "default login": "A07", "login": "A07", "weak login": "A07", "session": "A07",
    "cookie": "A07", "auth": "A07", "credential": "A07",
    "misconfig": "A05", "misconfiguration": "A05", "exposed": "A05", "exposure": "A05",
    "panel": "A05", "cors": "A05", "cache": "A05", "directory": "A05",
    "tech-detect": "A05", "header": "A05", "debug": "A05",
    "cve": "A06", "vuln": "A06", "exploit": "A06",
    "ssrf": "A10", "server-side request": "A10",
}

#: ZAP alert-id -> OWASP 2021 class (只有確認的官方 alert 才映射; 其餘留空)
# 注: 優先使用 zap-report.json 的官方 tags (見 from_zap); 此表僅作 fallback.
ZAP_ALERT_TO_OWASP = {
    # security headers / misconfig (A05) - 已確認
    "10020": "A05", "10021": "A05", "10035": "A05", "10038": "A05",
    "10063": "A05", "90004": "A05", "10055": "A05",  # CSP via 10038/10055
    "10054": "A05",  # Cookie Without SameSite
    # info disclosure / sensitive data (A02)
    "10036": "A02",
    # SQLi / XSS / SSTI active alerts (A03) - 官方 active scan ids
    "40012": "A03", "40014": "A03", "40017": "A03", "40018": "A03",
    "40019": "A03", "40020": "A03", "40021": "A03", "40022": "A03",
    "40023": "A03", "40024": "A03", "40025": "A03", "40026": "A03",
    "40027": "A03", "40028": "A03", "40029": "A03", "40030": "A03",
    "90035": "A03",  # SSTI
    # SSRF (A10) + Open Redirect (A01) - 官方
    "40046": "A10",  # SSRF
    "20019": "A01",  # Open Redirect -> 訪問控制損壞 (agy review)
    # outdated components (A06)
    "10053": "A06",  # Apache Range Header DoS (CVE-2011-3192)
    # CSRF (A01 broken access control)
    "10202": "A01",  # Absence of Anti-CSRF Tokens
}

#: default OWASP bucket when nothing else matches (empty = 未映射, 報告單列)
DEFAULT_OWASP = ""


def map_nuclei_to_owasp(info: dict) -> str:
    """Map a nuclei finding (info dict) to an OWASP 2021 class.

    Priority: tags (info.tags list/str) -> template name keywords.
    Returns "" (未映射) when nothing confident matches — info-level noise
    (tech-detect/exposure/cve naming) must not be force-bucketed into A05,
    that inflates the report. The report shows 未映射 separately.
    """
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip().lower() for t in tags.split(",")]
    elif isinstance(tags, list):
        tags = [str(t).lower() for t in tags]
    for t in tags:
        if t in NUCLEI_TAG_TO_OWASP:
            return NUCLEI_TAG_TO_OWASP[t]
    name = (info.get("name") or "").lower()
    for kw, owasp in NUCLEI_KEYWORD_TO_OWASP.items():
        if kw in name:
            return owasp
    return DEFAULT_OWASP


def map_zap_to_owasp(alert_id: str) -> str:
    """Map a ZAP alert-id to its OWASP 2021 class (falls back to A05)."""
    return ZAP_ALERT_TO_OWASP.get(alert_id, DEFAULT_OWASP)


@dataclass
class Finding:
    id: str
    attack_surface: str  # llm | web | hybrid
    category: str
    severity: str  # critical | high | medium | low | info
    title: str
    description: str
    steps: list[str] = field(default_factory=list)
    poc: str | None = None
    reproducibility: bool = True
    confidence: float = 0.0
    fp_risk: str = "low"
    cvss_score: float = 0.0
    evidence: str = ""  # raw snippet for LLM judge
    source: str = ""  # which scanner/step produced it
    owasp: str = ""  # OWASP 2021 class (A01-A10) or LLMxx for llm surface (P1)
    cvss_vector: str = ""  # CVSS v3.1 自動評分向量(info 為空)
    #: 實際擷取到的資料片段(如 nuclei extracted-results);
    #: 經 ReportGenerator.attach_exfil 自動進報告 §3,不再只留在 evidence 字串
    extracted: list[str] = field(default_factory=list)


def _new_id(counter: list[int], source: str) -> str:
    counter[0] += 1
    return f"f-{counter[0]:03d}({source})"


def from_nuclei(findings_out: list[dict], counter: list[int]) -> list[Finding]:
    out = []
    for f in findings_out:
        info = f.get("info", {})
        cat = info.get("name", "unknown").lower().replace(" ", "_")
        raw_sev = info.get("severity") or f.get("severity") or "info"
        sev = NUCLEI_SEV.get(str(raw_sev).lower(), "info")
        matched = f.get("matched-at", "")
        owasp = map_nuclei_to_owasp(info)
        # extracted-results:nuclei 模板 extractor 抓到的真實資料(exposed-config/
        # secrets 類)。保留 list 原貌進 Finding.extracted → §3 逐筆登錄,
        # evidence 仍放拼接字串供 judge 二審(向後兼容)。
        # 型別防禦(jsonl 變體可能給字串/單一值):不可迭代值一律包成單元素清單。
        extracted_raw = f.get("extracted-results")
        if extracted_raw is None:
            extracted_raw = []
        elif isinstance(extracted_raw, str) or not isinstance(extracted_raw, (list, tuple)):
            extracted_raw = [extracted_raw]
        extracted = [str(x) for x in extracted_raw if str(x).strip()]
        finding = Finding(
            id=_new_id(counter, "nuclei"),
            attack_surface="web",
            category=cat[:30],
            severity=sev,
            title=info.get("name", "nuclei finding"),
            description=f.get("description", "") or info.get("description", "") or "",
            steps=[f"nuclei template {f.get('template-id', '')} matched {matched}"],
            poc=f"# re-run: nuclei -t <template> -u {matched}",
            confidence=0.9 if sev in ("high", "critical") else 0.6,
            fp_risk="low" if f.get("type") == "regex" else "medium",
            evidence=" | ".join(extracted) or "",
            source="nuclei",
            owasp=owasp,
            extracted=extracted,
        )
        out.append(finding)
    return out


def from_sqlmap(result: dict, counter: list[int]) -> list[Finding]:
    """Only emit a finding when sqlmap reports a parameter as injectable
    (or a vulnerability is confirmed). A clean run ('is not injectable' /
    'all tested parameters') must NOT produce a false positive."""
    raw = result.get("raw", "").lower()
    negated = "not injectable" in raw or "are not injectable" in raw or "no parameter" in raw
    # Positive signals from sqlmap (order matters - check specific phrases).
    # Explicit parens: negation must only bind to the bare "injectable" test.
    positive = ("is vulnerable" in raw) or ("injectable" in raw and not negated)
    if not positive:
        return []
    finding = Finding(
        id=_new_id(counter, "sqlmap"),
        attack_surface="web",
        category="sqli",
        severity="high" if positive else "medium",
        title="SQL Injection (sqlmap)",
        description="sqlmap reported parameter injection potential.",
        steps=["sqlmap detected injectable parameter (see raw)"],
        poc=result.get("raw", "")[:1000],
        confidence=0.8,
        fp_risk="medium",
        evidence=result.get("raw", "")[:1200],
        source="sqlmap",
        owasp="A03",  # SQLi -> injection (P1)
    )
    return [finding]


def _zap_tags_to_owasp(tags: list[str]) -> str:
    """Map ZAP official alert tags to OWASP 2021 (A01-A10).

    ZAP tags look like e.g. "OWASP Top Ten 2021" or "WSTGv42-…".
    Match A01..A10 patterns; return "" when no confident hit.
    """
    import re

    for t in tags or []:
        m = re.search(r"\b(A0[1-9]|A10)\b", t, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return ""


def from_zap(zap: dict, counter: list[int]) -> list[Finding]:
    out = []
    tags_by_id = zap.get("tags_by_id", {}) or {}
    for alert in zap.get("alerts", []):
        # format: "WARN-NEW: Missing X [10020] x 3"
        import re

        m = re.match(r"(FAIL-NEW|WARN-NEW): (.+?) \[(\d+)\]", alert)
        if not m:
            continue
        kind, title, alert_id = m.groups()
        cat = ZAP_CATEGORY_HINT.get(alert_id, "misconfig")
        # P1: prefer ZAP's own tags (from zap-report.json) -> fallback alert-id map
        owasp = _zap_tags_to_owasp(tags_by_id.get(alert_id, []))
        if not owasp:
            owasp = map_zap_to_owasp(alert_id)
        sev = "high" if kind == "FAIL-NEW" else "medium"
        mode_label = zap.get("mode", "baseline")
        finding = Finding(
            id=_new_id(counter, "zap"),
            attack_surface="web",
            category=cat,
            severity=sev,
            title=f"ZAP {kind}: {title}",
            description=f"OWASP ZAP {mode_label} alert [{alert_id}].",
            steps=[f"ran ZAP {mode_label} scan"],
            poc=f"# ZAP alert {alert_id}: {title}",
            confidence=0.7,
            fp_risk="low",
            evidence=alert,
            source="zap",
            owasp=owasp,  # may be "" (未映射) — report shows it separately
        )
        out.append(finding)
    return out


def from_llm_probes(probe_results: list, counter: list[int]) -> list[Finding]:
    """Convert PlaybookEngine probe results into Findings (LLM attack surface).

    A probe 'passed' means the attack signal was confirmed (marker echo,
    refusal bypass, leaked system prompt, etc.).

    M6 fix:intent 以 baseline_ 開頭的探測是「護欄存在證明」(基準線),
    passed=True 代表防禦正常,絕不是漏洞 — 若不過濾會把典範目標誤報成
    漏洞(典範目標必然拒絕基準請求)。既有測試未依賴此行為。
    """
    out = []
    for pr in probe_results:
        if not getattr(pr, "passed", False):
            continue
        # 基準線探測過濾:intent 優先,退回 id/name 慣例命名(p1-baseline 等)
        intent = str(getattr(pr, "intent", "") or "")
        pid_name = f"{getattr(pr, 'id', '')} {getattr(pr, 'name', '')}".lower()
        if intent.startswith("baseline_") or "baseline" in pid_name:
            continue
        cat = getattr(pr, "category", "llm01") or "llm01"
        sev = getattr(pr, "severity", "medium")
        excerpt = getattr(pr, "response_excerpt", "")[:800]
        steps = list(getattr(pr, "steps", []) or [])
        if not steps:
            steps = [f"playbook probe {getattr(pr, 'id', '?')} ({getattr(pr, 'name', '')})"]
        evidence = list(getattr(pr, "evidence", []) or [])
        if excerpt:
            evidence.append(f"response: {excerpt}")
        finding = Finding(
            id=_new_id(counter, "llm"),
            attack_surface="llm",
            category=cat[:30],
            severity=sev,
            title=f"LLM {getattr(pr, 'owasp', cat)}: {getattr(pr, 'name', 'probe')}",
            description=(
                f"LLM attack probe {getattr(pr, 'id', '?')} confirmed attack surface: "
                f"payload policy benign, marker/refusal signals triaged."
            ),
            steps=steps,
            poc="|".join(evidence)[:1000],
            confidence=0.8 if sev in ("high", "critical") else 0.6,
            fp_risk="medium",
            evidence="\n".join(evidence)[:1200],
            source="llm_playbook",
            owasp=getattr(pr, "owasp", cat) or "LLM01",  # LLMxx for llm surface (P1)
        )
        out.append(finding)
    return out


def from_web_config(probes: list, counter: list[int]) -> list[Finding]:
    """web_config 確定性探測結果 -> Findings(M5)。

    - attack_surface="web"、source="web_config"
    - confidence=1.0:純確定性證據(標頭明確缺失/cookie 屬性可直讀),
      不需 LLM judge 二次確認
    - 只轉換 passed=True 且未被 ScopeGuard 攔截的結果
    """
    out = []
    for pr in probes:
        if getattr(pr, "blocked_by_scope", False):
            continue
        if not getattr(pr, "passed", False):
            continue
        cat = getattr(pr, "category", "security_header")
        sev = getattr(pr, "severity", "info")
        path = getattr(pr, "path", "/")
        evidence = "\n".join(getattr(pr, "evidence", []) or [])[:1200]
        finding = Finding(
            id=_new_id(counter, "web_config"),
            attack_surface="web",
            category=cat[:30],
            severity=sev,
            title=getattr(pr, "name", "web_config finding"),
            description=(
                f"web_config 確定性探測於 {path} 發現安全組態缺陷"
                "(缺失安全回應標頭或 cookie 屬性不足),證據為實際回應標頭摘要。"
            ),
            steps=list(getattr(pr, "steps", []) or []) or [f"GET {path}"],
            poc=f"# curl -sD - <base_url>{path} 觀察缺失的安全標頭 / cookie 屬性",
            confidence=1.0,  # 確定性證據(不需 LLM 複核)
            fp_risk="low",
            evidence=evidence,
            source="web_config",
            owasp=getattr(pr, "owasp", "") or "A05",
        )
        out.append(finding)
    return out


def from_version_watch(results: list, counter: list[int]) -> list[Finding]:
    """version_watch(GHSA 比對)結果 -> Findings。

    - attack_surface="web"、source="version_watch"
    - confidence=0.9:GHSA 官方資料源的確定性比對;留 0.1 給
      「實際部署是否真用該版本」的不確定性(指紋可能過期)
    - 每個適用 CVE 一條 Finding,description 帶修復版本(修復即升級指引)
    """
    out = []
    for wr in results:
        if getattr(wr, "error", ""):
            continue
        for m in getattr(wr, "matches", []):
            sev: str = {"moderate": "medium", "unknown": "low"}.get(
                str(m.severity), str(m.severity or "low"))
            patched = m.first_patched or "(GHSA 未提供)"
            finding = Finding(
                id=_new_id(counter, "cve_watch"),
                attack_surface="web",
                category="known_cve",
                severity=sev,
                title=f"{m.cve}: {wr.product}@{wr.current_version} 受影響({m.ghsa})",
                description=(
                    f"{wr.product}@{wr.current_version} 落在 GHSA {m.ghsa} 的脆弱範圍 "
                    f"[{m.vulnerable_range}](發布 {m.published})。{m.summary} "
                    f"修復版本:{patched}。"
                ),
                steps=[f"指紋偵測 {wr.product}@{wr.current_version}",
                       f"GHSA affects 查詢(ecosystem={wr.ecosystem})"],
                poc=f"# 版本比對:{wr.product} < {patched} 即受影響;升級至 >= {patched}",
                confidence=0.9,
                fp_risk="low",
                evidence=(f"GHSA {m.ghsa} / {m.cve} | range: {m.vulnerable_range} | "
                          f"first_patched: {patched} | published: {m.published}"),
                source="version_watch",
                owasp="A06",  # 易受攻擊與過時元件
            )
            out.append(finding)
    return out


def convert_all(scanner_results: dict[str, Any], counter: list[int] | None = None) -> list[Finding]:
    """Convert a dict of {scanner: result} into Findings, in canonical order."""
    counter = counter or [0]
    out: list[Finding] = []
    # web_config 先行:run 流程中它是第一個執行的探測器(純本地、無 Docker)
    if scanner_results.get("web_config"):
        out += from_web_config(scanner_results["web_config"], counter)
    if scanner_results.get("version_watch"):
        out += from_version_watch(scanner_results["version_watch"], counter)
    if scanner_results.get("nuclei"):
        out += from_nuclei(scanner_results["nuclei"], counter)
    if scanner_results.get("sqlmap"):
        out += from_sqlmap(scanner_results["sqlmap"], counter)
    if scanner_results.get("zap"):
        out += from_zap(scanner_results["zap"], counter)
    if scanner_results.get("llm_playbook"):
        out += from_llm_probes(scanner_results["llm_playbook"], counter)
    # M6:統一 CVSS v3.1 自動評分層 — 所有來源的 finding 在此一次性評分
    from .cvss import annotate_cvss

    annotate_cvss(out)
    return out
