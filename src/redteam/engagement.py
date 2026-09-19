"""作戰紀律包(Engagement Package)— 借鑑 Decepticon:先定紀律,再放行。

Decepticon 的核心差異化主張:「紅隊與 script kiddie 的分別在於紀律」—
第一個封包離網之前,先產出完整 engagement package(RoE / OPPLAN /
範圍與除外 / MITRE ATT&CK 對應),之後每個動作都在已定義的規則內執行。

Tanli 取其輕量可移植部分(不引入 Postgres/Neo4j/LangGraph):
- Rules of Engagement(RoE):目標範圍、允許方法、速率限制、除外項、
  資料處理與緊急聯絡,寫成可稽核的 YAML/JSON 檔,run 時載入並強制。
- OPPLAN:依目標類型產生行動計畫(階段、每階段目標、對應 MITRE
  ATT&CK / OWASP 技術編號),agent 的 system prompt 直接注入。
- ScopeGuard 仍是唯一物理圍籬;RoE 是「紙面+prompt 層」的第二道
  紀律(速率/方法/除外項在此宣告,ScopeGuard/read-only 兜底)。

設計原則:RoE 檔可為空(向後兼容,CLI 未指定時走預設 localhost-only
紀律,與現行行為一致)。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

#: MITRE ATT&CK / 對應表(階段 → 技術)。僅收錄 Tanli 工具能實際觸及的
#: 技術,避免虛張聲勢;每階段附 ATT&CK technique id 供報告映射。
OPPLAN_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "web_service": [
        {"phase": "recon", "objective": "識別真實元件/框架/版本假設(指紋,不採信自報)",
         "tactic": "TA0043 Reconnaissance", "techniques": ["T1595.001 Active Scanning: Scanning IP Blocks",
                                                            "T1592 Gather Victim Host Information"]},
        {"phase": "discovery", "objective": "攻擊面列舉:設定檔探測、暴露路徑、方法政策",
         "tactic": "TA0007 Discovery", "techniques": ["T1592.004 Host Information: Client Config"]},
        {"phase": "vuln_intel", "objective": "產品級 CVE 全量查詢(GHSA+OSV+NVD),交叉核實版本",
         "tactic": "TA0043 Reconnaissance", "techniques": ["T1595.002 Vulnerability Scanning"]},
        {"phase": "verification", "objective": "動態驗證候選 CVE(nuclei tag / 安全探測),",
         "tactic": "TA0001 Initial Access", "techniques": ["T1190 Exploit Public-Facing Application"]},
        {"phase": "report", "objective": "證據鏈 findings + CVSS + 修復建議",
         "tactic": "(Reporting)", "techniques": []},
    ],
    "llm_app": [
        {"phase": "recon", "objective": "識別 LLM 應用形態:chat/completion/embedding/RAG/MCP 端點",
         "tactic": "TA0043 Reconnaissance", "techniques": ["T1595 Active Scanning"]},
        {"phase": "injection", "objective": "Prompt injection / 系統提示外洩(良性探針,模擬 payload)",
         "tactic": "TA0001 Initial Access", "techniques": ["T1059.007 Input Interception (LLM analogue)"]},
        {"phase": "leakage", "objective": "訓練資料/上下文/RAG 資料外洩檢查",
         "tactic": "TA0009 Collection", "techniques": ["T1005 Data from Local System (analogue)"]},
        {"phase": "report", "objective": "OWASP LLM Top10 映射 + 證據鏈",
         "tactic": "(Reporting)", "techniques": []},
    ],
}

DEFAULT_ROE: dict[str, Any] = {
    "engagement_id": "",
    "operator": "",
    "authorized_targets": [],          # 空 = 交由 ScopeGuard 決定(未簽憑證→localhost-only)
    "allowed_methods": ["GET", "HEAD", "OPTIONS"],
    "read_only": True,
    "rate_limit_qps": 10,
    "max_probes": 60,
    "max_steps": 30,
    "token_budget": 200000,
    "excluded_paths": ["/logout", "/delete", "/admin/dangerous"],
    "data_handling": "僅記錄必要證據;金鑰/個資一律遮蔽(redaction);原始回應 24h 內刪除",
    "deconfliction": "如發現 critical 立即停止對該端點探測並回報",
    "emergency_contact": "",
    "hours": "不限制(自行承擔噪音影響)",
}


@dataclass
class RoE:
    """可稽核的參戰規則。from_file 載入;as_prompt_block 注入 agent。"""
    raw: dict = field(default_factory=lambda: dict(DEFAULT_ROE))
    source: str = "(default)"

    @classmethod
    def load(cls, path: str | Path | None) -> "RoE":
        if not path:
            return cls()
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"RoE 檔不存在: {p}")
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError(f"RoE 必須是 YAML mapping: {p}")
        merged = {**DEFAULT_ROE, **data}
        return cls(raw=merged, source=str(p))

    def merged(self) -> dict:
        return dict(self.raw)

    @property
    def read_only(self) -> bool:
        return bool(self.raw.get("read_only", True))

    def as_prompt_block(self) -> str:
        """注入 agent system prompt 的紀律宣告(Decepticon 式:行動前已定界)。"""
        r = self.raw
        lines = [
            "=== RULES OF ENGAGEMENT (binding; source: %s) ===" % self.source,
            f"engagement_id: {r.get('engagement_id') or '(ad-hoc)'}",
            f"authorized targets: {', '.join(r.get('authorized_targets') or []) or '(delegated to ScopeGuard)'}",
            f"allowed methods: {', '.join(r.get('allowed_methods') or [])}",
            f"read_only: {r.get('read_only')}  rate limit: {r.get('rate_limit_qps')} qps",
            f"budgets: <={r.get('max_steps')} steps, <={r.get('max_probes')} probes, "
            f"<={r.get('token_budget')} tokens",
            f"excluded paths: {', '.join(r.get('excluded_paths') or []) or '(none)'}",
            f"data handling: {r.get('data_handling')}",
            f"deconfliction: {r.get('deconfliction')}",
            "Violating RoE = the assessment is void. If a needed action is outside RoE,",
            "record it in the summary as a blocked recommendation — never do it silently.",
        ]
        return "\n".join(lines)


def build_opplan(target_type: str, roe: RoE) -> str:
    """產生 OPPLAN 文本(階段+目標+ATT&CK 映射),供 prompt 注入與報告附錄。"""
    phases = OPPLAN_TEMPLATES.get(target_type) or OPPLAN_TEMPLATES["web_service"]
    lines = [f"=== OPPLAN (target_type={target_type}) ===",
             f"engagement: {roe.raw.get('engagement_id') or '(ad-hoc)'}",
             "Execute phases in order; adapt tactics to what you observe — the plan",
             "is a contract of intent, not a script. Cite technique ids in findings."]
    for i, ph in enumerate(phases, 1):
        t = "; ".join(ph["techniques"]) or "—"
        lines.append(f"{i}. [{ph['phase']}] {ph['objective']}  ({ph['tactic']} | {t})")
    return "\n".join(lines)


def detect_target_type(hint: str) -> str:
    h = (hint or "").lower()
    if any(k in h for k in ("llm", "chat", "gpt", "rag", "openai", "completion", "mcp")):
        return "llm_app"
    return "web_service"


def save_engagement_package(out_dir: str | Path, target: str, roe: RoE,
                            opplan_text: str) -> Path:
    """把紀律包寫入工作區(可稽核存證)。回傳檔案路徑。"""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    pkg = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "target": target,
        "roe_source": roe.source,
        "roe": roe.merged(),
        "opplan": opplan_text,
    }
    p = out / "engagement_package.json"
    p.write_text(json.dumps(pkg, ensure_ascii=False, indent=1), encoding="utf-8")
    return p


def new_roe_template(path: str | Path) -> Path:
    """產生可編輯的 RoE YAML 範本(tanli roe --init)。"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    sample = dict(DEFAULT_ROE)
    sample["engagement_id"] = "eng-YYYYMMDD-01"
    sample["operator"] = "<筆名/代號>"
    sample["authorized_targets"] = ["127.0.0.1", "localhost"]
    p.write_text(
        "# Tanli Rules of Engagement — 參戰規則(行動前必須存在且經確認)\n"
        + yaml.safe_dump(sample, allow_unicode=True, sort_keys=False),
        encoding="utf-8")
    return p
