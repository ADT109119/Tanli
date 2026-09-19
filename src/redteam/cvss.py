"""CVSS v3.1 base score — 確定性評分層(M6,規格書 §9/§11 Phase 3)。

設計原則:
- 官方公式純 stdlib 實作,Roundup 為**無條件進位**到小數第一位(非四捨五入),
  並用整數 epsilon 處理浮點誤差(0.35 在 binary float 略大於 0.35 的陷阱)。
- 自動評分採「severity → 預設向量 → 官方公式算分」的誠實路線:
  向量由 `severity_to_vector()` 查表產生(每條理由都寫在註解),
  報告端必須標示「自動評分、High/Critical 待人工複核」,
  避免讀者誤以為是逐項人工評定。
- info 級不評分(0.0 / 空向量):資訊類發現不該稀釋 CVSS 統計。
"""

from __future__ import annotations

import math
import re

CVSS31_PREFIX = "CVSS:3.1"

# 官方 CVSS v3.1 指標權重(§CVSS-SPEC-3 Table 15-18)
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
# PR 權重依 Scope 不同:Scope Changed 時高權限的成本較低
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_METRIC_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
_METRIC_VALUES = {
    "AV": set(_AV),
    "AC": set(_AC),
    "PR": set(_PR_UNCHANGED),
    "UI": set(_UI),
    "S": {"U", "C"},
    "C": set(_CIA),
    "I": set(_CIA),
    "A": set(_CIA),
}


def roundup(x: float) -> float:
    """CVSS 官方 Roundup:無條件進位到小數點第一位。

    直接 math.ceil(x*10) 會被浮點誤差咬(例如 4.1999999999*10=41.999…
    或 0.35*10 略大於 3.5 的情況),故先在 1e-9 網格上量化再進位。
    """
    return math.ceil(round(x * 10, 9)) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    """解析 CVSS:3.1 向量字串為 {指標: 值};格式/值非法一律 raise ValueError。

    fail-closed:任何解析不了的輸入都拒絕(回傳值只有成功一途),
    避免「解析失敗→預設值」把打錯的向量變成低分或高分。
    """
    if not isinstance(vector, str) or not vector.startswith(CVSS31_PREFIX + "/"):
        raise ValueError(f"不是合法的 CVSS 3.1 向量(需以 {CVSS31_PREFIX}/ 開頭): {vector!r}")
    parts = vector.split("/")[1:]
    out: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            raise ValueError(f"向量段落缺少 ':': {part!r}")
        k, v = part.split(":", 1)
        if k not in _METRIC_VALUES:
            raise ValueError(f"未知指標: {k!r}")
        if v not in _METRIC_VALUES[k]:
            raise ValueError(f"指標 {k} 的值非法: {v!r}")
        out[k] = v
    missing = [m for m in _METRIC_ORDER if m not in out]
    if missing:
        raise ValueError(f"向量缺少指標: {missing}")
    return out


def score_from_vector(vector: str) -> float:
    """依官方公式計算 CVSS v3.1 base score(0.0–10.0)。

    公式逐字對照 FIRST 官方規範 v3.1 §7.1(first.org/cvss/v3.1/specification-document):
      ISS = 1 − [(1−C)(1−I)(1−A)]
      Impact(Scope U) = 6.42 × ISS
      Impact(Scope C) = 7.52 × (ISS−0.029) − 3.25 × (ISS−0.02)^15
      Exploitability = 8.22 × AV × AC × PR × UI
      BaseScore = Impact ≤ 0 → 0
                  Scope U → Roundup(min(Impact + Exploitability, 10))
                  Scope C → Roundup(min(1.08 × (Impact + Exploitability), 10))
    (注意:Scope C 用 1.08 乘數;1.25×Impact 是 CVSS v2 的舊公式,不可混用。
     (ISS×0.9731−0.02)^13 只出現在環境分數的 Modified Impact,與 base 無關。)
    """
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
    iss = 1.0 - (1.0 - _CIA[m["C"]]) * (1.0 - _CIA[m["I"]]) * (1.0 - _CIA[m["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    # 官方規定:Impact <= 0 時 Base Score 直接為 0(例如 C:N/I:N/A:N)
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_table[m["PR"]] * _UI[m["UI"]]
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    return roundup(base)


# ---------------------------------------------------------------------------
# severity/category → 預設向量查表(自動評分)
# ---------------------------------------------------------------------------
# 每條向量的理由寫在行尾註解。原則:
#   critical = 遠端可直接達成完整主機/資料淪陷(模擬 RCE/全庫外洩)
#   high     = 遠端可讀寫敏感資料但非完全控制(如敏感資訊外洩/繞過認證)
#   medium   = 有限度的機密性損失,需使用者互動或局部條件(標頭缺失、弱 cookie)
#   low      = 難利用或影響侷限(指紋揭露、過度快取)
#   info     = 不評分(空向量)
_DEFAULT_VECTORS: dict[str, str] = {
    # 注入類(RCE/全庫讀取):AV:N 免互動直接打穿,C/I/A 全失守
    "critical": f"{CVSS31_PREFIX}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    # 高危:遠端讀取敏感資料為主(I 保留部分完整性的場景由類別覆寫)
    "high": f"{CVSS31_PREFIX}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    # 中危:需使用者互動(點擊/正常瀏覽)才吃到,機密性局部損失
    "medium": f"{CVSS31_PREFIX}/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    # 低危:利用條件刁鑽(AC:H)、影響侷限
    "low": f"{CVSS31_PREFIX}/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    # 資訊類:不評分
    "info": "",
}

#: 類別關鍵字 → 覆寫向量(比 severity 預設更貼近該弱點的真實影響)
_CATEGORY_VECTORS: dict[str, str] = {
    # 注入一律按最壞情況:免互動、全失守(與 LLM prompt injection 同級)
    "injection": f"{CVSS31_PREFIX}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "sqli": f"{CVSS31_PREFIX}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "rce": f"{CVSS31_PREFIX}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "command-injection": f"{CVSS31_PREFIX}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    # 安全標頭缺失:通常要搭配社工/XSS 鏈才吃到 → UI:R + 局部機密損失;
    # 點擊劫持(XFO)明確是用戶被誘騙點擊 → UI:R
    "security_header": f"{CVSS31_PREFIX}/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "weak_cookie": f"{CVSS31_PREFIX}/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    # 弱 cookie 屬性(HttpOnly/Secure 缺失):需 XSS/中間人鏈才吃到 → UI:R 局部機密
    "cookie_attr": f"{CVSS31_PREFIX}/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    # 指紋/版本揭露:本身不直接洩密,提供攻擊情報 → 低分
    "info_disclosure": f"{CVSS31_PREFIX}/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    # 過度快取:共享快取汙染的機密損失有限且條件式
    "cache_policy": f"{CVSS31_PREFIX}/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    # LLM 注入面:提示注入可完全繞過護欄取得模型輸出 → 按高危偏上
    "llm01": f"{CVSS31_PREFIX}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    # 敏感資訊外洩(系統提示/金鑰洩漏):機密性高、完整度不受影響
    "llm02": f"{CVSS31_PREFIX}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    # 過度代理:模型自曝工具/計畫,機密局部 + 潛在後續完整度風險
    "llm03": f"{CVSS31_PREFIX}/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    # 隱含上下文外洩(RAG 間接注入):與 LLM01 同族
    "llm08": f"{CVSS31_PREFIX}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    # 輸出不安全處理(XSS/markdown):下游執行需使用者互動 → UI:R
    "llm10": f"{CVSS31_PREFIX}/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
}

_VECTOR_RE = re.compile(r"^CVSS:3\.1(?:/[A-Z]{1,2}:[^/]+)+$")


def severity_to_vector(severity: str, category: str = "", attack_surface: str = "") -> str:
    """查表產生該 finding 的預設 CVSS v3.1 向量(自動評分)。

    優先級:類別覆寫(貼近弱點本質)> severity 預設。info/未知一律空向量。
    注意:這是「以嚴重度與類別推導」的自動向量,不是逐項人工評定;
    報告端必須誠實標示(見 report.py 的人工複核門禁)。
    """
    sev = (severity or "").lower()
    if sev == "info" or sev not in _DEFAULT_VECTORS:
        return ""
    cat = (category or "").lower()
    # 先做類別覆寫(含注入關鍵字偵測:category 常是自由文本如 sql_injection)
    for key, vec in _CATEGORY_VECTORS.items():
        if key in cat:
            return vec
    if attack_surface == "llm" and sev in _DEFAULT_VECTORS:
        # LLM 面沒有命中具體 llmxx 時,基準線給高危級(注入面普遍高影響)
        return _DEFAULT_VECTORS["high"] if sev in ("critical", "high") else _DEFAULT_VECTORS[sev]
    return _DEFAULT_VECTORS[sev]


def _band(score: float) -> str:
    """CVSS 官方嚴重度分級帶。"""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


#: 嚴重度 → 期望分數帶(自動評分的一致性檢查)
_EXPECTED_BAND = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def annotate_cvss(findings: list) -> None:
    """就地為每個 Finding 填入 cvss_vector / cvss_score(自動評分)。

    - info 或未匹配到向量的 finding:0.0 / 空向量(不污染統計)。
    - 一致性保護:類別覆寫向量若算出的分數脫離該 finding 嚴重度的分數帶
      (例如 low 卻算出 Medium 級),退回 severity 預設向量,
      保證「嚴重度標籤」與「CVSS 分數」永不自相矛盾。
    - 向量解析/算分失敗一律降為不評分並保留向量空字串——安全工具裡
      「算不出來」必須顯現為 0 分而不是 crash,也不能給假分數。
    """
    for f in findings:
        sev = (getattr(f, "severity", "info") or "").lower()
        cat = getattr(f, "category", "")
        surface = getattr(f, "attack_surface", "")
        if sev == "info" or sev not in _EXPECTED_BAND:
            f.cvss_vector = ""
            f.cvss_score = 0.0
            continue
        vec = severity_to_vector(sev, cat, surface)
        # 類別覆寫向量若與嚴重度分數帶不符 → 退回嚴重度預設向量
        try:
            score = score_from_vector(vec) if vec else 0.0
        except ValueError:
            score = -1.0
        if vec and _band(score) != _EXPECTED_BAND[sev]:
            vec = _DEFAULT_VECTORS[sev]
            score = score_from_vector(vec)
        if not vec or score < 0:
            f.cvss_vector = ""
            f.cvss_score = 0.0
            continue
        f.cvss_vector = vec
        f.cvss_score = score
