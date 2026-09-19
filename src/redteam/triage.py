"""Finding Triage 風險分 — 借鑑 RedAmon CypherFix Triage Agent。

CypherFix 的固定風險模型:真實性 × 被利用可能性 × 影響 × 可達性。
模型只做「因子修正」,分數由固定公式計算 — 沒有 LLM 也能完整排序
(這點對 Tanli 至關重要:triage 必須確定性可稽核,預算為零也能跑)。

Tanli 精簡為可確定的因子:
  risk = impact(severity 基礎分)
       × truthfulness(信心度,confidence)
       × exploit_likelihood(EPSS 分數;CVE 無 EPSS 資料時用 severity 預設)
       × reachability(暴露面:直接可達=1.0,需先決條件遞減)
  KEV 命中 → likelihood 強制拉到 0.9(真實世界已在被打)。

輸出 triage_score(0~10)+ 因子分解,寫入報告排序依據。全部純函數,
無 LLM、無網路(EPSS 由呼叫端傳入,缺資料如實以 None 標記)。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SEVERITY_BASE = {"critical": 10.0, "high": 7.5, "medium": 5.0,
                 "low": 2.5, "info": 1.0}

#: 無 EPSS 資料時,以嚴重度隱含的利用可能性(保守預設)。
DEFAULT_LIKELIHOOD = {"critical": 0.8, "high": 0.6, "medium": 0.35,
                      "low": 0.15, "info": 0.05}

#: 可達性:發現需要多少先決條件才能被實際濫用。
REACHABILITY = {
    "direct": 1.0,        # 未授權即可直達(公網端點/無認證)
    "low_priv": 0.8,      # 需低權限帳號
    "auth_required": 0.6,  # 需一般認證
    "user_interaction": 0.5,  # 需誘使使用者動作
    "internal_only": 0.3,   # 僅內網可達
}


@dataclass
class TriageResult:
    score: float               # 0~10(1 decimal)
    factors: dict[str, float]
    kev: bool = False
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"triage_score": self.score, "factors": self.factors,
                "kev": self.kev, "note": self.note}


def triage(*, severity: str, confidence: float,
           cve_epss: float | None = None, kev: bool = False,
           reachability: str = "direct") -> TriageResult:
    """固定公式 triage;所有因子分解透明可稽核。"""
    sev = (severity or "info").lower()
    impact = SEVERITY_BASE.get(sev, 1.0)
    truth = min(max(confidence, 0.0), 1.0)
    if kev:
        likelihood, l_note = 0.9, "KEV 命中:likelihood 固定 0.9(真實利用中)"
    elif cve_epss is not None:
        # EPSS→likelihood:0.9 分位數映射,保底 0.1 避免 EPSS≈0 直接歸零
        likelihood = max(0.1, min(1.0, cve_epss * 1.2))
        l_note = f"EPSS={cve_epss:.4f}"
    else:
        likelihood = DEFAULT_LIKELIHOOD.get(sev, 0.2)
        l_note = "無 EPSS 資料 → severity 隱含預設(如實標註)"
    reach = REACHABILITY.get(reachability, 0.6)
    score = round(impact * truth * likelihood * reach, 1)
    factors = {"impact": impact, "truthfulness": round(truth, 2),
               "likelihood": round(likelihood, 3), "reachability": reach}
    note = "; ".join(filter(None, [l_note, f"reachability={reachability}"]))
    if score >= 7.5:
        note += "; 建議立即處置"
    return TriageResult(score=score, factors=factors, kev=kev, note=note)


def sort_findings(items: list[dict], score_key: str = "triage_score") -> list[dict]:
    """報告排序:triage 分 → severity → cvss。缺分數者沉底但不丟棄。"""
    sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

    def key(d: dict):
        return (float(d.get(score_key, -1) or -1),
                sev_rank.get(str(d.get("severity", "info")).lower(), 0),
                float(d.get("cvss_score", 0) or 0))
    return sorted(items, key=key, reverse=True)
