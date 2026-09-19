"""報告完善測試(M6 Phase 3)- CVSS 向量展示、人工複核門禁、修復建議。"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from redteam.cvss import annotate_cvss
from redteam.findings import Finding
from redteam.report import ReportGenerator


def _mk(fid, sev, cat, owasp="", surface="web", desc="d"):
    f = Finding(
        id=fid, attack_surface=surface, category=cat, severity=sev,
        title=f"t-{fid}", description=desc, steps=["s1"], poc="poc",
        owasp=owasp,
    )
    return f


def _gen(findings):
    r = ReportGenerator("http://127.0.0.1/lab", "web_service")
    for f in findings:
        r.add_finding(f)
    return r.render()


def test_cvss_vector_displayed():
    fs = [_mk("f-1", "high", "sqli", "A03")]
    annotate_cvss(fs)
    out = _gen(fs)
    assert "CVSS:3.1/" in out
    # CVSS 分數不為 0(接線 bug 修復後必須真的帶分進報告)
    assert "CVSS: 0.0" not in out
    assert f"CVSS: {fs[0].cvss_score} (CVSS:3.1/" in out


def test_info_finding_has_no_vector():
    fs = [_mk("f-2", "info", "fingerprint", "A06")]
    annotate_cvss(fs)
    out = _gen(fs)
    assert "CVSS: 0.0" in out  # info 不評分,只顯示 0.0 無向量


def test_human_review_gate_markers():
    fs = [
        _mk("f-c", "critical", "rce", "A03"),
        _mk("f-h", "high", "sqli", "A03"),
        _mk("f-m", "medium", "security_header", "A05"),
        _mk("f-l", "low", "cookie_attr", "A05"),
    ]
    annotate_cvss(fs)
    out = _gen(fs)
    assert "高危待人工複核: 2 項" in out
    assert "人工複核: 待確認(自動評分,定稿前需人工確認)" in out
    assert "人工複核: auto-scored" in out


def test_remediation_section_concrete():
    fs = [
        _mk("f-1", "medium", "security_header", "A05"),
        _mk("f-2", "low", "cookie_attr", "A05"),
        _mk("f-3", "high", "llm01", "LLM01", surface="llm"),
    ]
    annotate_cvss(fs)
    out = _gen(fs)
    sec6 = out.split("## 6. 修復建議", 1)[1]
    # 不再是佔位文字
    assert "待每項 finding 補" not in sec6
    # 各 finding 的建議與 id 清單都必須出現
    assert "f-1" in sec6 and "f-3" in sec6
    assert "Strict-Transport-Security" in sec6  # security_header 建議
    assert "HttpOnly" in sec6                    # cookie_attr 建議
    assert "注入" in sec6                        # LLM01 建議


def test_remediation_dedup_and_generic():
    # 同一建議(security_header)兩項 finding → 建議只列一次但 id 都在
    fs = [
        _mk("f-a", "medium", "security_header", "A05"),
        _mk("f-b", "medium", "security_header", "A05"),
        _mk("f-c", "low", "mystery_cat", "ZZ9"),  # 對照表外 → 通用建議
    ]
    annotate_cvss(fs)
    out = _gen(fs)
    sec6 = out.split("## 6. 修復建議", 1)[1]
    assert "f-a, f-b" in sec6          # 去重彙整
    assert "重掃回歸確認閉合" in sec6   # 通用建議兜底
