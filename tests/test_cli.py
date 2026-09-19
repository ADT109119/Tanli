"""CLI 整合測試(M5) — self-test 命令應 exit 0。"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from typer.testing import CliRunner

from redteam.cli import app

runner = CliRunner()


def test_self_test_exits_zero():
    """self-test 起本地靶場並通過全數斷言 → exit 0。

    全程不需 Docker / 外部網路 / LLM API key(127.0.0.1 除外)。
    """
    result = runner.invoke(app, ["self-test"])
    assert result.exit_code == 0, result.output
    assert "[PASS]" in result.output
    assert "全部通過" in result.output


def test_run_help_lists_web_config_scanner():
    """--scanners 的 help 應列出 web_config(M5 新增選項)。"""
    result = runner.invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    assert "web_config" in result.output


def test_self_test_covers_m6_assertions():
    """self-test 輸出必須包含 M6 新增斷言(LLM 靶場 e2e + CVSS/修復建議)。"""
    result = runner.invoke(app, ["self-test"])
    assert result.exit_code == 0, result.output
    assert "vulnerable LLM 靶場" in result.output
    assert "hardened LLM 靶場" in result.output
    assert "CVSS v3.1 向量與實質修復建議" in result.output


def test_run_help_lists_nuclei_limit_options():
    """P3 限縮選項應出現在 run/scan 的 help。"""
    for cmd in (["run", "--help"], ["scan", "--help"]):
        result = runner.invoke(app, cmd)
        assert result.exit_code == 0
        assert "--nuclei-severity" in result.output
        assert "--nuclei-exclude-protocols" in result.output


def test_report_file_written_contains_cvss_and_remediation(tmp_path):
    """(agy review 補強)實體報告檔必須真的寫出 CVSS 向量與修復建議。"""
    from redteam.report import Finding, ReportGenerator

    r = ReportGenerator("http://127.0.0.1/test", "web_service")
    r.add_finding(Finding(
        id="f-1", attack_surface="web", category="security_header",
        severity="medium", title="Header missing", description="desc",
        steps=["GET /"], cvss_score=4.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", owasp="A05",
    ))
    out_file = r.write(out_dir=str(tmp_path))
    content = out_file.read_text(encoding="utf-8")
    assert "CVSS:3.1/" in content
    assert "Strict-Transport-Security" in content
    # 草稿狀態行:無高危 → 明示無高危發現
    assert "狀態" in content and "無高危發現" in content


def test_report_draft_status_for_high_risk():
    """(agy review 補強)含 high/critical 時報告必須標草稿 + 大小寫不敏感。"""
    from redteam.report import Finding, ReportGenerator

    r = ReportGenerator("http://127.0.0.1/test", "web_service")
    # 故意用大寫 "High"/"CRITICAL"(上游 scanner 可能這樣回)
    for i, sev in enumerate(("High", "CRITICAL")):
        r.add_finding(Finding(
            id=f"f-{i}", attack_surface="web", category="sqli",
            severity=sev, title="t", description="d", steps=["s"],
            owasp="A03",
        ))
    out = r.render()
    assert "草稿" in out and "定稿前需人工複核" in out
    # 大寫值也必須拿到 CVSS 評分(annotate 層 lower 正規化)
    from redteam.cvss import annotate_cvss

    annotate_cvss([f for f in r.findings])
    assert all(f.cvss_score > 0 for f in r.findings)
    # 大寫值不得漏標人工複核(auto-scored 不得出現在 high/critical 上)
    out2 = r.render()
    assert "高危待人工複核: 2 項" in out2
