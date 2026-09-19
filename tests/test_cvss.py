"""CVSS v3.1 評分層測試(M6)— 純離線,無外部依賴。

官方參考值同時用 `cvss` 權威庫交叉驗證(僅測試用,非 runtime 依賴)。
值與 FIRST 官方規範 v3.1 §7.1 及 `cvss` 庫一致。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

from redteam.cvss import (
    annotate_cvss,
    parse_vector,
    score_from_vector,
    severity_to_vector,
)
from redteam.findings import Finding


# ---------------------------------------------------------------------------
# 官方公式正確性(值與 FIRST 官方規範 v3.1 §7.1 及 `cvss` 庫一致)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "vector,expected",
    [
        # 全失守(RCE 典型)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        # Scope Changed 全失守(Log4Shell 級)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        # 純可用性打斷(DoS 典型)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        # 本地提權典型
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        # 需低權限讀敏感資料
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
        # 免互動 + Scope Changed + 局部機密(驗證 1.08 乘數分支)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        # 難利用低危(驗證 v3.1 Scope-C Impact 公式)
        ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:N", 2.6),
        # CIA 全無 → 0 分(Impact<=0 規則)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_official_vectors(vector, expected):
    assert score_from_vector(vector) == pytest.approx(expected)


def test_cross_check_with_authoritative_lib():
    """對一批向量與 `cvss` 權威庫結果必須完全一致(若環境缺庫則跳過)。"""
    cvss_lib = pytest.importorskip("cvss")
    vectors = [
        "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:H/A:N",
        "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:L/A:N",
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L",
    ]
    for v in vectors:
        assert score_from_vector(v) == pytest.approx(float(cvss_lib.CVSS3(v).base_score))


# ---------------------------------------------------------------------------
# 向量解析 fail-closed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "bad",
    [
        "",
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 缺前綴
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # 缺 A
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 非法值
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Q/C:H/I:H/A:H",  # 非法 scope
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/X:1",  # 未知指標
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 版本不符
    ],
)
def test_parse_vector_rejects(bad):
    with pytest.raises(ValueError):
        parse_vector(bad)


def test_roundup_is_ceiling_not_round():
    """Roundup 為無條件進位:4.02→4.1,4.00→4.0(官方例子)。"""
    from redteam.cvss import roundup

    assert roundup(4.02) == 4.1
    assert roundup(4.00) == 4.0
    assert roundup(4.0000001) == 4.1


# ---------------------------------------------------------------------------
# 自動評分:severity → 向量 + annotate_cvss
# ---------------------------------------------------------------------------

def test_severity_to_vector_basics():
    assert severity_to_vector("info") == ""
    assert severity_to_vector("critical").startswith("CVSS:3.1/")
    # 注入類一律最壞情況
    assert "C:H/I:H/A:H" in severity_to_vector("low", "sql_injection", "web")
    # 安全標頭類帶 UI:R(需用戶互動鏈)
    assert "UI:R" in severity_to_vector("medium", "security_header", "web")


def _f(sev, cat="misc", surface="web"):
    return Finding(
        id="f-test", attack_surface=surface, category=cat, severity=sev,
        title="t", description="d",
    )


def test_annotate_cvss_scores_and_bands():
    findings = [
        _f("critical", "rce"), _f("high", "info_disclosure"),
        _f("medium", "security_header"), _f("low", "cookie_attr"),
        _f("info", "security_header"),
    ]
    annotate_cvss(findings)
    assert findings[4].cvss_score == 0.0 and findings[4].cvss_vector == ""
    for f in findings[:4]:
        assert f.cvss_score > 0
        assert f.cvss_vector.startswith("CVSS:3.1/")
    # 嚴重度分數帶一致性:critical>high>medium>low>0
    assert findings[0].cvss_score > findings[1].cvss_score > findings[2].cvss_score >= findings[3].cvss_score > 0


def test_annotate_consistency_band_clamp():
    """類別覆寫向量若脫離嚴重度分數帶 → 退回嚴重度預設(low 不會拿到高分)。"""
    low_f = _f("low", "injection")  # injection 覆寫向量=9.8,但 low 分帶上限 4.0
    annotate_cvss([low_f])
    assert low_f.cvss_score < 4.0, "low 標籤必須被 clamp 回 Low 分帶"


def test_convert_all_annotates_every_source():
    """convert_all 輸出(含 nuclei/zap 等)全部帶上 CVSS 評分。"""
    from redteam.findings import convert_all

    nuclei_results = [{
        "template-id": "t1", "matched-at": "http://127.0.0.1/x",
        "info": {"name": "SQLi detected", "severity": "high", "tags": ["sqli"]},
    }]
    out = convert_all({"nuclei": nuclei_results})
    assert out and out[0].cvss_score > 0 and out[0].cvss_vector.startswith("CVSS:3.1/")
