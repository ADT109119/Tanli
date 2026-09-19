"""Report generator - spec §11 Markdown deliverable.

Structure: header (audit), exec summary, reproduction/PoC, exfiltrated data/achieved,
vulnerability details, remediation. Redaction of sensitive data.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    id: str
    attack_surface: str  # llm | web | hybrid
    category: str
    severity: str  # critical | high | medium | low | info
    title: str
    description: str
    steps: list[str]
    poc: str | None = None
    reproducibility: bool = True
    confidence: float = 0.0
    fp_risk: str = "low"
    cvss_score: float = 0.0
    owasp: str = ""  # OWASP 2021 class (A01-A10) or LLMxx for llm surface (P1)
    cvss_vector: str = ""  # CVSS v3.1 自動評分向量(由 cvss.annotate_cvss 填入)


def redact(data: str, mode: str = "auto") -> str:
    """Spec §11 redaction: API keys/JWT/cookies masked. Disable with --full."""
    if mode == "full":
        return data
    # API key / token: keep first4 last4
    data = re.sub(r"(sk-[A-Za-z0-9]{4})[A-Za-z0-9]+([A-Za-z0-9]{4})", r"\1****\2", data)
    # JWT: keep only the header prefix + last4 of signature; mask payload & sig body
    data = re.sub(r"(eyJ[A-Za-z0-9_-]{4})[A-Za-z0-9_-]*\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{4})[A-Za-z0-9_-]*", r"\1.****.\3", data)
    # Bearer tokens / Authorization headers
    data = re.sub(r"(Bearer\s+)[A-Za-z0-9._-]{8,}", r"\1****", data, flags=re.IGNORECASE)
    # Cookie header values (name=value pairs)
    data = re.sub(r"(Cookie:\s*[^=;\s]+)=[^;\s]+", r"\1=****", data)
    # AWS-style access keys
    data = re.sub(r"(AKIA[0-9A-Z]{4})[0-9A-Z]+", r"\1****", data)
    return data


#: §6 修復建議對照表(繁體中文、可執行)。優先級:
#:   finding category 關鍵字(REMEDIATION_BY_CATEGORY)> OWASP/LLMxx 類別
#:   (REMEDIATION_BY_OWASP)> 通用建議。
REMEDIATION_BY_CATEGORY: dict[str, str] = {
    "security_header": (
        "於反向代理或應用層統一補齊安全回應標頭:CSP(由 report-only 起步)、"
        "Strict-Transport-Security(https)、X-Frame-Options: DENY 或 CSP frame-ancestors、"
        "X-Content-Type-Options: nosniff、Referrer-Policy: no-referrer/same-origin。"
    ),
    "cookie_attr": (
        "Session cookie 一律加上 HttpOnly 與 Secure(https 環境),並視需要加 "
        "SameSite=Lax/Strict;確認 session id 為高熵隨機值且登出即失效。"
    ),
    "cache_policy": (
        "對含個人資訊或驗證後的回應加 Cache-Control: no-store;反向代理避免將"
        "驗證後頁面寫入共享快取,並定期快取爆破(Cache busting)保護。"
    ),
    "info_disclosure": (
        "移除或混淆版本指紋(Server/X-Powered-By 標頭、錯誤頁堆疊追蹤、目錄索引),"
        "生產環境關閉 debug 模式與詳細錯誤輸出。"
    ),
    "injection": (
        "改用參數化查詢/預編譯陳述式與輸出編碼;對所有外部輸入做白名單驗證;"
        "以最小權限帳號執行資料庫與系統指令。"
    ),
    # agy review:nuclei 常產出 category="sqli"/"rce"(自由文本),
    # 別名必須指向同一注入建議,否則未映射 OWASP 時會退回通用建議
    "sqli": (
        "改用參數化查詢/預編譯陳述式與輸出編碼;對所有外部輸入做白名單驗證;"
        "以最小權限帳號執行資料庫與系統指令。"
    ),
    "rce": (
        "改用參數化查詢/預編譯陳述式與輸出編碼;對所有外部輸入做白名單驗證;"
        "以最小權限帳號執行資料庫與系統指令。"
    ),
    "command-injection": (
        "改用參數化查詢/預編譯陳述式與輸出編碼;對所有外部輸入做白名單驗證;"
        "以最小權限帳號執行資料庫與系統指令。"
    ),
    "llm01": (
        "對 LLM 輸入做注入防護:系統提示與外部內容以明確定界分隔,套用輸入過濾"
        "與輸出標記偵測;關鍵操作不得僅依賴模型輸出授權,需外部權限系統把關。"
    ),
    "llm02": (
        "系統提示與內部指令視為敏感配置:避免在提示內嵌金鑰/內網地址;對回應做"
        "系統提示特徵偵測與遮蔽,並定期以洩漏探測回歸測試。"
    ),
    "llm03": (
        "工具/函式呼叫需白名單 + 人工核准高影響操作;模型自曝工具清單時視為"
        "資訊洩漏,對 agent 執行層施加獨立授權檢查。"
    ),
    "llm08": (
        "RAG/文件索引內容視同不可信輸入:入庫前過濾指示型內容,檢索片段以定界"
        "標記包裹,並在系統提示聲明「文件內容僅作資料不作指令」。"
    ),
    "llm10": (
        "模型輸出渲染前一律 HTML escape 或走白名單 sanitizer;禁用 markdown "
        "直出 HTML、javascript: URL 與內嵌事件屬性;內容安全策略(CSP)兜底。"
    ),
}

REMEDIATION_BY_OWASP: dict[str, str] = {
    "A01": "以伺服器端為主的存取控制(deny-by-default)覆蓋所有端點;資源存取前驗證"
           "擁有關係,並對 IDOR 類參數改用不可列舉的間接參考。",
    "A02": "全鏈路 TLS(禁用降級協議)、敏感資料以強加密靜態儲存;金鑰集中管理並定期"
           "輪換;傳輸前對個資做最小化。",
    "A03": "所有解釋器呼叫改參數化 API;對輸入做白名單驗證與編碼;啟用 WAF 規則並"
           "於 CI 加入注入回歸測試。",
    "A04": "於設計階段進行威脅建模(STRIDE),將高風險流程(付款、認證、限額)的"
           "防護寫成不變式並納入測試。",
    "A05": "建立可重覆的加固基線(鏡像/組態即程式碼),移除預設憑證與示範頁面,"
           "以自動化組態掃描納入 CI/CD 把關。",
    "A06": "建立元件清單(SBOM)並追蹤 CVE;固定依賴版本並排程升級;移除未使用的"
           "元件與端點。",
    "A07": "強制多因素認證、密碼強度與洩漏密碼庫檢查;失敗次數限流與鎖定;"
           "session 逾時與登出失效。",
    "A08": "軟體供應鏈驗證:產物簽章與散列校驗、CI 來源鎖定;資料完整性以"
           "簽章/校驗和保護,關鍵更新走雙重核准。",
    "A09": "補齊安全事件日誌(認證、授權失敗、管理操作)並接入告警;定期演練"
           "回應流程,保留足夠鑑識資訊。",
    "A10": "SSRF 防護:URL 白名單 + 拒絕內網/元資料位址(169.254.169.254)、"
           "禁止重定向追隨、以受控代理執行外部抓取。",
    "LLM01": "提示注入防護:外部內容定界、輸入過濾、關鍵操作獨立授權(詳見類別建議)。",
    "LLM02": "系統提示與內部資料按敏感資訊管理,回覆前做特徵遮蔽與洩漏檢測。",
    "LLM03": "過度代理防護:工具白名單、高影響操作人工核准、獨立授權層。",
    "LLM08": "隱含上下文(RAG)內容視同不可信,入庫過濾 + 檢索定界 + 系統提示聲明。",
    "LLM10": "模型輸出渲染前 escape/sanitize,禁用直出 HTML 與危險 URL 協定。",
}

_GENERIC_REMEDIATION = (
    "與維運確認此項的風險接受度,於修復後以本工具重掃回歸確認閉合。"
)


def _remediation_for(f) -> str:
    """挑選一項 finding 的修復建議:類別關鍵字 > OWASP/LLMxx > 通用。"""
    cat = (getattr(f, "category", "") or "").lower()
    for key, advice in REMEDIATION_BY_CATEGORY.items():
        if key in cat:
            return advice
    owasp = (getattr(f, "owasp", "") or "").upper()
    if owasp in REMEDIATION_BY_OWASP:
        return REMEDIATION_BY_OWASP[owasp]
    # LLMxx 前綴匹配(LLM01x 等變體)
    if owasp.startswith("LLM"):
        for key, advice in REMEDIATION_BY_OWASP.items():
            if key.startswith("LLM") and owasp[:5] == key[:5]:
                return advice
    return _GENERIC_REMEDIATION


class ReportGenerator:
    def __init__(self, target: str, target_type: str, redact_mode: str = "auto"):
        self.target = target
        self.target_type = target_type
        self.redact_mode = redact_mode
        self.findings: list[Finding] = []
        self.records: list[Any] = []
        self.exfiltrated: list[str] = []
        self.achieved: list[str] = []

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)

    def add_exfil(self, data: str, redact_mode: str = "auto") -> None:
        self.exfiltrated.append(redact(data, redact_mode))

    def _severity_count(self) -> str:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            # agy review:大寫 severity("High")不得 crash/漏計 → lower() 正規化
            sev = (getattr(f, "severity", "") or "").lower()
            if sev in counts:
                counts[sev] += 1
        return ", ".join(f"{k}={v}" for k, v in counts.items())

    def _owasp_counts(self) -> dict[str, int]:
        """Count findings per OWASP class (A01-A10 + LLMxx), web & llm grouped."""
        counts: dict[str, int] = {}
        for f in self.findings:
            key = f.owasp or "未映射"
            # map full owasp strings (e.g. "LLM01") -> short class
            counts[key] = counts.get(key, 0) + 1
        return counts

    def render(self, audit: dict | None = None) -> str:
        audit = audit or {}
        owasp_counts = self._owasp_counts()
        # M6 人工複核門禁(規格書 §9):High/Critical 自動評分需人工確認後才可定稿
        # agy review:判定一律 lower() 正規化,防上游回傳 "High"/"CRITICAL" 大寫值
        # 時漏標人工複核(資安工具的 fail-open 是不可接受的)
        def _sev(x) -> str:
            return (getattr(x, "severity", "") or "").lower()

        review_needed = [f for f in self.findings if _sev(f) in ("high", "critical")]
        lines = [
            f"# 紅隊測試報告 — {self.target}",
            "",
            # 草稿狀態行:CI/自動化管線據此辨識「未定稿」(agy review)
            f"> **狀態**: {'草稿 — 含 ' + str(len(review_needed)) + ' 項高危/嚴重自動評分發現,定稿前需人工複核' if review_needed else '無高危發現'}",
            f"> **稽核資訊**: 授權 token hash `{audit.get('auth_hash', '-')}` | Scope: `{audit.get('scope', '-')}` | 測試者: `{audit.get('tester', '-')}`",
            f"> **時間線**: {audit.get('started', '-')} → {audit.get('ended', '-')}",
            "",
            "## 1. 執行摘要",
            f"- 目標: `{self.target}` | 類型: `{self.target_type}`",
            f"- 發現總計: {len(self.findings)} ({self._severity_count()})",
            "- **OWASP 2021 聚合**: " + (
                ", ".join(f"{k}:{v}" for k, v in sorted(owasp_counts.items())) or "(無發現)"
            ),
            f"- 高危待人工複核: {len(review_needed)} 項"
            + ("(定稿前需人工確認自動評分)" if review_needed else ""),
            "",
            "## 2. 複現方式 / PoC",
        ]
        for f in self.findings:
            owasp_label = f" | OWASP: **{f.owasp or '-'}**" if f.owasp else ""
            cvss_label = (
                f"{f.cvss_score} ({f.cvss_vector})" if f.cvss_vector else f"{f.cvss_score}"
            )
            lines.append(f"### {f.id}: {f.title}")
            lines.append(f"- 類別: {f.category} | 嚴重: {f.severity} | CVSS: {cvss_label}{owasp_label}")
            # 人工複核門禁標示:High/Critical 必經人工確認;Low/Medium 自動評分標記
            if _sev(f) in ("high", "critical"):
                lines.append("- 人工複核: 待確認(自動評分,定稿前需人工確認)")
            elif _sev(f) in ("low", "medium"):
                lines.append("- 人工複核: auto-scored")
            for i, s in enumerate(f.steps, 1):
                lines.append(f"{i}. {redact(s, self.redact_mode)}")
            if f.poc:
                lines.append(f"```bash\n{redact(f.poc, self.redact_mode)}\n```")
            if f.description:
                lines.append(f"> {redact(f.description, self.redact_mode)}")
            lines.append("")
        lines += [
            "## 3. 偷到的資料 / 達成的結果",
            "**Extracted data (redacted):**",
        ]
        for e in self.exfiltrated:
            lines.append(f"- `{e}`")
        lines += ["**Achieved:**"] + [f"- {a}" for a in self.achieved] + [
            "",
            "## 4. 漏洞詳情",
            "| ID | OWASP | 類別 | 嚴重 | CVSS | 可復現 |",
            "|:--|:--|:--|:--|:--|:--|",
        ]
        for f in self.findings:
            lines.append(f"| {f.id} | {f.owasp or '-'} | {f.category} | {f.severity} | {f.cvss_score} | {f.reproducibility} |")
        lines += [
            "",
            "## 5. OWASP 2021 覆蓋度聚合",
            "| OWASP | 類別 | 發現數 |",
            "|:--|:--|:--|",
        ]
        from .findings import OWASP_NAMES
        for owasp in sorted(owasp_counts):
            name = OWASP_NAMES.get(owasp, owasp)
            lines.append(f"| {owasp} | {name} | {owasp_counts[owasp]} |")
        if not owasp_counts:
            lines.append("| - | 無發現 | 0 |")
        lines += [
            "",
            "## 6. 修復建議",
        ]
        # 依 finding 去重彙整:同一建議只列一次,附受影響 finding id 清單
        advice_map: dict[str, list[str]] = {}
        for f in self.findings:
            advice_map.setdefault(_remediation_for(f), []).append(f.id)
        if advice_map:
            for advice, ids in advice_map.items():
                lines.append(f"- **{', '.join(ids)}**:{advice}")
        else:
            lines.append("- 本次無發現,無需修復項目。")
        lines += [
            "",
        ]
        return "\n".join(lines)

    def write(self, out_dir: str = ".") -> Path:
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = Path(out_dir) / f"report_{self.target.replace('://', '_').replace('/', '_')}_{ts}.md"
        path.write_text(self.render())
        return path
