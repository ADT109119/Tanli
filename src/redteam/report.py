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
    #: 該 finding 實際擷取到的資料片段(nuclei extracted-results / agent 登錄),
    #: render 時彙進 §3;由 ReportGenerator.attach_exfil 自動填充掃描器路徑
    extracted: list[str] = field(default_factory=list)


#: Set-Cookie 的屬性旗標(值非機密,遮蔽後可讀性優先);其餘 name=value 一律遮值
_COOKIE_ATTR_KEYS = {"path", "domain", "samesite", "max-age", "expires"}


def _mask_cookie_pairs(match: re.Match) -> str:
    prefix, value = match.group(1), match.group(2)
    masked = []
    for pair in value.split(";"):
        k, sep, _v = pair.partition("=")
        if sep and k.strip().lower() not in _COOKIE_ATTR_KEYS:
            masked.append(f"{k}=****")
        else:
            masked.append(pair)  # 旗標(Secure/HttpOnly)與已知屬性原樣保留
    return prefix + ";".join(masked)


def redact(data: str, mode: str = "auto") -> str:
    """Spec §11 redaction: API keys/JWT/cookies masked. Disable with --full.

    硬化(agy review 2026-09-21,exfil 閉環使 redact 成為安全關鍵路徑):
    sk- 字元集涵蓋 sk-proj-/sk-ant- 等帶連字號金鑰;Bearer 支援完整
    Base64 字元集(+/=);Cookie 大小寫不敏感且逐對遮蔽全部 name=value。
    """
    if mode == "full":
        return data
    # API key / token: keep first4 last4;含連字號/底線變體(sk-proj-…, sk-ant-…)
    data = re.sub(r"(sk-[A-Za-z0-9_-]{4})[A-Za-z0-9_-]+([A-Za-z0-9_-]{4})", r"\1****\2", data)
    # JWT: keep only the header prefix + last4 of signature; mask payload & sig body
    data = re.sub(r"(eyJ[A-Za-z0-9_-]{4})[A-Za-z0-9_-]*\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{4})[A-Za-z0-9_-]*", r"\1.****.\3", data)
    # Bearer tokens / Authorization headers:完整 Base64 字元集,防 + 或 = 後段裸露
    data = re.sub(r"(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}", r"\1****", data, flags=re.IGNORECASE)
    # Cookie / Set-Cookie 標頭:大小寫不敏感(HTTP/2 為小寫),逐對遮蔽所有 name=value,
    # 只保留 Path/Domain/SameSite/Max-Age/Expires 等非機密屬性
    data = re.sub(r"((?:Set-)?Cookie:\s*)([^\r\n]+)", _mask_cookie_pairs, data,
                  flags=re.IGNORECASE)
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
    # agent 自由文本類別別名(實測:agent 常寫 "Broken Access Control /
    # Unauthenticated Data Access"、"broken_access_control" 等,舊表全數
    # miss 退回通用話術)→ 指向與 OWASP A01/A05 相同的具體建議
    # ⚠ 順序:必須列在 "config" 之前——混合類別字串(如 "access control
    #   misconfiguration")可能同時含兩子字串,dict 迭代順序決定命中;
    #   未授權存取優先於組態建議(v0.0.3 實測教訓)
    "access control": (
        "以伺服器端為主的存取控制(deny-by-default)覆蓋所有端點;資源存取前驗證"
        "擁有關係,並對 IDOR 類參數改用不可列舉的間接參考。"
    ),
    "access_control": (
        "以伺服器端為主的存取控制(deny-by-default)覆蓋所有端點;資源存取前驗證"
        "擁有關係,並對 IDOR 類參數改用不可列舉的間接參考。"
    ),
    "idor": (
        "以伺服器端為主的存取控制(deny-by-default)覆蓋所有端點;資源存取前驗證"
        "擁有關係,並對 IDOR 類參數改用不可列舉的間接參考。"
    ),
    "unauth": (
        "在伺服器端(而非前端 JS)為每個資料端點補上統一的 session/授權檢查,"
        "未授權一律回傳 401/導向登入;不得以可猜參數(卡號+生日)代替憑證。"
    ),
    "config": (
        "建立可重覆的加固基線(鏡像/組態即程式碼),移除預設憑證與示範頁面,"
        "以自動化組態掃描納入 CI/CD 把關。"
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
        # exfil 去重錨點:記「原始值」(非遮罩後)。兩條前四後四相同的真金鑰
        # 遮罩後同形,若按遮罩後去重會誤丟第二條真實擷取物;redact 對已遮罩
        # 文本天然冪等,故原始值去重不破壞重複 attach 的冪等性。
        self._exfil_seen: set[str] = set()

    def add_finding(self, f: Any) -> None:
        # 註:findings.Finding 與本模組 Finding 是兩個 dataclass(欄位子集相容),
        # cli 橋接層一直傳 findings.Finding 進來。duck-typing 如實反映現狀,
        # render() 只讀它實際用到的欄位。
        self.findings.append(f)

    def add_exfil(self, data: str, redact_mode: str | None = None) -> None:
        # 統一入口(agy review):strip + 去重(以原始值為錨)+ 預設沿用實例
        # redact_mode,避免手動登錄與 attach 的脫敏策略分裂。
        s = str(data).strip()
        if not s or s in self._exfil_seen:
            return
        self._exfil_seen.add(s)
        self.exfiltrated.append(redact(s, self.redact_mode if redact_mode is None else redact_mode))

    def attach_exfil(self, findings: list[Any] | None = None) -> int:
        """把 finding.extracted 逐筆登錄進 §3(exfiltrated),走既有 redact 脫敏。

        去重後回填,回傳新增筆數。這是「擷取資料 → 正式報告 §3」的閉環入口:
        掃描器路徑由 convert 後調用,agent 路徑由 add_finding 的 exfiltrated_data
        走同一通道(見 agent.py),確保真實擷取物不再只留在 free-text evidence。
        """
        items = []
        for f in findings if findings is not None else self.findings:
            for raw in (getattr(f, "extracted", None) or []):
                # 多行片段拆成單一條目,§3 的 code-span 條列才不會被斷行撕開
                items.extend(ln for ln in str(raw).splitlines() if ln.strip())
        added = 0
        for d in items:
            d = d.strip()
            if not d or d in self._exfil_seen:
                continue
            self.add_exfil(d, self.redact_mode)
            added += 1
        return added

    def _severity_count(self) -> str:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            # agy review:大寫 severity("High")不得 crash/漏計 → lower() 正規化
            sev = (getattr(f, "severity", "") or "").lower()
            if sev in counts:
                counts[sev] += 1
        return ", ".join(f"{k}={v}" for k, v in counts.items())

    def _owasp_counts(self) -> dict[str, int]:
        """Count findings per OWASP class (A01-A10 + LLMxx), web & llm grouped.

        agent 常把 OWASP 寫成自由文字(如 "OWASP A01:2021 — Broken Access
        Control"),此處正規化抽取 A0x/LLMxx code;抽不到才計「未映射」。
        """
        counts: dict[str, int] = {}
        for f in self.findings:
            # owasp 欄優先;agent 也常把 OWASP code 塞進自由文本 category,一併掃
            raw = (f.owasp or "") + " " + (f.category or "")
            m = re.search(r"\b(A0[1-9]|A10|LLM\d{2})\b", raw.upper())
            key = m.group(1) if m else ((f.owasp or "").strip() or "未映射")
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
        if not self.findings:
            status_line = "無發現"
        elif review_needed:
            status_line = (f"草稿 — 含 {len(review_needed)} 項高危/嚴重自動評分發現,"
                           "定稿前需人工複核")
        else:
            # 修復:舊版只認 high/critical,medium/low 存在時誤寫「無高危發現」
            # 讓人誤讀成整份報告沒東西。改為如實統計。
            status_line = (f"完成 — {len(self.findings)} 項發現"
                           f"({self._severity_count()}),無須人工複核之高危項")
        lines = [
            f"# 紅隊測試報告 — {self.target}",
            "",
            # 草稿狀態行:CI/自動化管線據此辨識「未定稿」(agy review)
            f"> **狀態**: {status_line}",
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
        ]
        if self.redact_mode == "full":
            # --full:此章節是未脫敏原樣資料,標題如實宣告(防誤當已脫敏擴散)
            lines.append("**Extracted data (UNREDACTED — --full enabled):**")
            lines.append("> [!CAUTION] 本節包含未脫敏機密資料,請妥善保管,勿直接轉發。")
        else:
            lines.append("**Extracted data (redacted):**")
        for e in self.exfiltrated:
            # 反引號會提前閉合 code-span(agy review):含 ` 的片段改用雙反引號包裹
            tick = "``" if "`" in e else "`"
            pad = " " if tick == "``" else ""
            lines.append(f"- {tick}{pad}{e}{pad}{tick}")
        if not self.exfiltrated:
            lines.append("- (本次評估未登錄實際擷取資料)")
        lines.append("**Achieved:**")
        for a in self.achieved:
            lines.append(f"- {a}")
        if not self.achieved:
            lines.append("- (無)")
        lines += [
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

    def write(self, out_dir: str = ".", audit: dict | None = None) -> Path:
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = Path(out_dir) / f"report_{self.target.replace('://', '_').replace('/', '_')}_{ts}.md"
        path.write_text(self.render(audit=audit))
        return path
