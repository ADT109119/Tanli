"""Tests for the scanner bridge layer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from redteam.scanners import ScannerBridge, ScannerJob


def test_submit_creates_job():
    bridge = ScannerBridge()
    job = bridge.sqlmap_runner("http://127.0.0.1:8080/login")
    assert isinstance(job, ScannerJob)
    assert job.scanner == "sqlmap"
    assert "-u" in job.args
    assert "--batch" in job.args
    assert job.status == "queued"
    assert job.job_id in bridge.jobs


def test_nuclei_runner_args():
    bridge = ScannerBridge()
    job = bridge.nuclei_runner("http://127.0.0.1:8080", tags="sql-injection")
    assert job.scanner == "nuclei"
    assert "-u" in job.args
    assert "-tags" in job.args
    assert "-jsonl" in job.args


def test_nuclei_runner_default_limits():
    """P3 限縮預設:排除 info 級 + 排除非 web 協議(保留 ssl,不傷 A02)。"""
    bridge = ScannerBridge()
    job = bridge.nuclei_runner("http://127.0.0.1:8080")
    i = job.args.index("-severity")
    assert job.args[i + 1] == "low,medium,high,critical"
    j = job.args.index("-exclude-type")
    excl = job.args[j + 1]
    assert "dns" in excl and "file" in excl
    assert "ssl" not in excl.split(","), "不得排除 ssl(A02 TLS 覆蓋倒退)"
    assert "http" not in excl.split(",")


def test_nuclei_runner_overrides():
    """顯式覆寫生效;空字串代表關閉該限縮(fail-open 由呼叫端明說)。"""
    bridge = ScannerBridge()
    job = bridge.nuclei_runner("http://127.0.0.1:8080", severity="critical",
                               exclude_protocols="")
    assert job.args[job.args.index("-severity") + 1] == "critical"
    assert "-exclude-protocols" not in job.args


def test_nuclei_template_dir_http_priority(tmp_path, monkeypatch):
    """P3 限縮:templates/http/ 存在 → -t 指向 /workspace/templates/http。"""
    (tmp_path / "http").mkdir()
    (tmp_path / "http" / "a.yaml").write_text("id: a")
    (tmp_path / "dns").mkdir()
    (tmp_path / "dns" / "b.yaml").write_text("id: b")
    assert ScannerBridge._select_nuclei_template_dir(tmp_path) == "/workspace/templates/http"
    # 無 http/ 子目錄 → 退回全量根目錄
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "c.yaml").write_text("id: c")
    assert ScannerBridge._select_nuclei_template_dir(plain) == "/workspace/templates"
    # 空目錄 → None(走內建模板,呼叫端須警告)
    empty = tmp_path / "empty"
    empty.mkdir()
    assert ScannerBridge._select_nuclei_template_dir(empty) is None


def test_zap_runner_args():
    bridge = ScannerBridge()
    job = bridge.zap_api_scan("http://127.0.0.1:8080")
    assert job.scanner == "zap"
    assert "-t" in job.args


def test_parse_nuclei_jsonl():
    sample = (
        '{"template-id":"sql-injection","info":{"name":"SQL Injection"},"severity":"high","matched-at":"http://x/?id=1"}\n'
        '{"template-id":"xss","info":{"name":"XSS"},"severity":"medium","matched-at":"http://x/?q=1"}\n'
    )
    results = ScannerBridge._parse_nuclei_jsonl(sample)
    assert len(results) == 2
    assert results[0]["severity"] == "high"
    assert results[1]["info"]["name"] == "XSS"


def test_rewrite_localhost():
    assert ScannerBridge._rewrite_localhost("http://127.0.0.1:8095/?id=1") == "http://host.docker.internal:8095/?id=1"
    assert ScannerBridge._rewrite_localhost("http://localhost/x") == "http://host.docker.internal/x"
    assert ScannerBridge._rewrite_localhost("https://example.com/x") == "https://example.com/x"


def test_parse_zap_summary():
    sample = (
        "WARN-NEW: Missing Anti-clickjacking Header [10020] x 2\n\thttp://x/ (200 OK)\n"
        "FAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 7\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: 60"
    )
    result = ScannerBridge._parse_zap_summary(sample)
    assert result["warn"] == 7
    assert result["fail"] == 0
    assert any("Anti-clickjacking" in a for a in result["alerts"])


# ---------------------------------------------------------------------------
# P2: ZAP full-scan 模式
# ---------------------------------------------------------------------------

def test_zap_baseline_mode_default():
    bridge = ScannerBridge()
    job = bridge.zap_api_scan("http://127.0.0.1:8080")
    assert job.mode == "baseline"
    assert "-s" not in job.args  # baseline 不加 -s / active flags


def test_zap_full_mode_args():
    bridge = ScannerBridge()
    job = bridge.zap_api_scan("http://127.0.0.1:8080", mode="full")
    assert job.mode == "full"
    # full-scan: -J report + -s short output + -m/-T bounds + -I ignore warn exit
    assert "-J" in job.args
    assert "-m" in job.args
    assert "-T" in job.args
    assert "-I" in job.args
    assert "-s" in job.args
    # baseline 與 full 的 args 不同
    base = bridge.zap_api_scan("http://127.0.0.1:8080", mode="baseline")
    assert base.args != job.args


def test_zap_api_mode_requires_format():
    bridge = ScannerBridge()
    # 不給 -f -> 現在直接 raise (agy review: fail fast 而非容器 crash)
    try:
        bridge.zap_api_scan("http://127.0.0.1:8080/openapi.json", mode="api")
        assert False, "should raise ValueError"
    except ValueError:
        pass
    # 給合法 -f -> 參數帶上
    job2 = bridge.zap_api_scan("http://127.0.0.1:8080/openapi.json", mode="api",
                               api_format="openapi")
    assert "-f" in job2.args and "openapi" in job2.args
    # 非法 format -> raise
    try:
        bridge.zap_api_scan("http://x/openapi.json", mode="api", api_format="swagger")
        assert False, "should raise ValueError"
    except ValueError:
        pass


def test_zap_invalid_mode_raises():
    bridge = ScannerBridge()
    try:
        bridge.zap_api_scan("http://127.0.0.1:8080", mode="invalid")
        assert False, "should raise"
    except ValueError:
        pass


def test_zap_job_has_mode():
    bridge = ScannerBridge()
    job = bridge.zap_api_scan("http://127.0.0.1:8080", mode="full")
    assert job.mode == "full"  # _exec 用 mode 選擇 entrypoint


def test_parse_zap_summary_with_tags_report(tmp_path):
    """_parse_zap_summary 能從（可選）zap-report.json 讀官方 tags."""
    report = tmp_path / "zap-report.json"
    report.write_text(
        '{"site":[{"alerts":[{"pluginid":"10020","tags":["OWASP Top Ten 2021","A07"]},'
        '{"pluginid":"40046","tags":["A10"]}]}]}'
    )
    sample = "WARN-NEW: X [10020] x 1\nFAIL-NEW: 0\tWARN-NEW: 1"
    result = ScannerBridge._parse_zap_summary(sample, json_path=str(report))
    assert result["tags_by_id"]["10020"] == ["OWASP Top Ten 2021", "A07"]
    assert result["tags_by_id"]["40046"] == ["A10"]

    # 文件不存在 -> 空 tags, 不崩潰
    result2 = ScannerBridge._parse_zap_summary(sample, json_path=str(tmp_path / "nope.json"))
    assert result2["tags_by_id"] == {}
