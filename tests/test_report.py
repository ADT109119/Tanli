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


def _sec3(text: str) -> str:
    return text.split("## 3.", 1)[1].split("## 4.", 1)[0]


def test_exfil_section_empty_placeholder():
    # 未登錄擷取物時 §3 必須明示「未登錄」,而不是留白(舊版死碼的症狀)
    out = _gen([_mk("f-x", "low", "info_disclosure", "A05")])
    sec3 = _sec3(out)
    assert "(本次評估未登錄實際擷取資料)" in sec3
    assert "**Achieved:**" in sec3 and "- (無)" in sec3


def test_attach_exfil_closes_loop_with_redaction():
    # exfil 閉環:finding.extracted → attach_exfil → §3 逐字出現且自動脫敏
    f = _mk("f-e", "high", "info_disclosure", "A05")
    f.extracted = [
        'api_key = "sk-demo0000000000000000000000001234"',
        "exfil_canary = REDTEAM_EXFIL_CANARY_9f3a",
    ]
    r = ReportGenerator("http://127.0.0.1/lab", "web_service")
    r.add_finding(f)
    n = r.attach_exfil()
    assert n == 2
    # 冪等:重複調用不重複登錄
    assert r.attach_exfil() == 0
    sec3 = _sec3(r.render())
    assert "REDTEAM_EXFIL_CANARY_9f3a" in sec3
    assert "sk-demo****1234" in sec3          # sk- 金鑰中段遮罩
    assert "00000000000000000000000" not in sec3


def test_add_exfil_direct_still_works():
    # 直接調用 add_exfil(掃描器以外來源/手工登錄)通道不變
    r = ReportGenerator("http://127.0.0.1/lab", "web_service")
    r.add_exfil("Bearer abcdefghijklmnop")
    sec3 = _sec3(r.render())
    assert "Bearer ****" in sec3
    assert "ijklmnop" not in sec3


def test_attach_exfil_explicit_findings_arg():
    # 可傳入尚未 add_finding 的清單(例如 triage 前預登錄)
    f = _mk("f-y", "high", "sqli", "A03")
    f.extracted = ["row: alice|secret-a"]
    r = ReportGenerator("http://127.0.0.1/lab", "web_service")
    assert r.attach_exfil([f]) == 1
    assert "row: alice|secret-a" in _sec3(r.render())


def test_redact_hardened_patterns():
    """redact 硬化回歸(agy review P0-1):exfil 閉環後 redact 是安全關鍵路徑。"""
    from redteam.report import redact

    # 現代帶連字號金鑰:sk-proj- / sk-ant- 必須被遮罩(舊字元集漏掉它們)
    out = redact("key=sk-proj-XXXXXXXXXXyyyyyyyyyyyyZZZZ1234 done")
    assert "****" in out and "yyyyyyyyyyyy" not in out
    out = redact("sk-ant-apiaaaa-BBBBccccDDDDeeeeFFFF1234")
    assert "BBBBccccDDDDeeee" not in out
    # Bearer:含 + / = 的 Base64 token 不得半遮半露
    out = redact("Authorization: Bearer aaaaaaaa+bbbbbbbb==cccc")
    assert "bbbbbbbb" not in out and "cccc" not in out
    # Cookie:小寫標頭(HTTP/2)+ 多對值全部遮罩,只留非機密屬性
    out = redact("cookie: a=1; session=TOPSECRET123; Path=/; HttpOnly; Secure")
    assert "TOPSECRET123" not in out
    assert "session=****" in out and "a=****" in out
    assert "Path=/" in out and "HttpOnly" in out  # 屬性保留可讀
    out = redact("Set-Cookie: sid=leakedvalue; Path=/; SameSite=Lax")
    assert "leakedvalue" not in out and "SameSite=Lax" in out
    # AKIA 回歸不破
    assert "SECRET12345678" not in redact("AKIASECRET12345678")


def test_add_exfil_dedup_strip_and_instance_mode():
    """add_exfil 統一入口(agy review P1-4):去重+strip+沿用實例 redact_mode。"""
    r = ReportGenerator("http://127.0.0.1/lab", "web_service")
    r.add_exfil("  secret-line  ")
    r.add_exfil("secret-line")          # strip 後重複 → 不得二次登錄
    assert len(r.exfiltrated) == 1
    # redact_mode="full" 實例:手動登錄同樣不遮罩(策略不分裂)
    rf = ReportGenerator("http://127.0.0.1/lab", "web_service", redact_mode="full")
    rf.add_exfil("sk-live1234567890abcd")
    assert "sk-live1234567890abcd" in rf.exfiltrated[0]
    # --full 實例的 §3 標題必須如實宣告 UNREDACTED
    body = rf.render()
    assert "UNREDACTED" in body and "勿直接轉發" in body


def test_exfil_markdown_backtick_escaping():
    """含反引號的擷取片段不得提前閉合 code-span(agy review P2-7)。"""
    r = ReportGenerator("http://127.0.0.1/lab", "web_service")
    r.add_exfil("SELECT * FROM `users`")
    sec3 = _sec3(r.render())
    assert "`` SELECT * FROM `users` ``" in sec3



def test_write_out_dir_creates_nested_dirs(tmp_path):
    """--report-dir 回歸:v0.0.3 前 write() 對不存在的目錄直接炸。"""
    r = ReportGenerator("http://127.0.0.1/lab", "web_service")
    r.add_finding(_mk("f-d1", "high", "sqli", "A03"))
    out = r.write(out_dir=str(tmp_path / "a" / "b"))
    assert out.parent == tmp_path / "a" / "b"
    assert out.exists() and out.read_text(encoding="utf-8").startswith("#")


def test_write_out_dir_default_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = ReportGenerator("http://127.0.0.1/lab", "web_service")
    out = r.write()
    assert out.resolve().parent == tmp_path.resolve() and out.exists()
