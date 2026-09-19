"""read-only 模式 / auth-header / version_watch 三項功能測試(2026-09-18 實務需求)。

全程 127.0.0.1(TargetLab)或純函數,無 Docker、無真實外網 GHSA 查詢。
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

from redteam.findings import convert_all
from redteam.interactor import RedTeamHTTP, SAFE_METHODS, ScopeGuard
from redteam.playbook import LLMTarget, PlaybookEngine, load_playbooks
from redteam.target_lab import TargetLab
from redteam.version_watch import detect_releases, version_in_range, version_lt, watch

REPO = Path(__file__).parent.parent
PB1 = str(REPO / "playbooks" / "llm" / "playbook_1.yaml")


# ---------------------------------------------------------------------------
# 1. read-only:HTTP 層物理封鎖
# ---------------------------------------------------------------------------

def test_readonly_blocks_post_but_allows_get():
    with TargetLab(behavior="vulnerable") as lab:
        http = RedTeamHTTP(guard=None, read_only=True)
        rec_post = http.request("POST", lab.base_url + "/v1/chat/completions",
                                json={"model": "x", "messages": []})
        assert rec_post.blocked_by_readonly is True
        assert rec_post.status is None  # 請求根本未離網
        rec_get = http.request("GET", lab.base_url + "/v1/chat/completions")
        # GET 不受 read-only 封鎖(即使靶場回 4xx 也證明請求已離網)
        assert rec_get.blocked_by_readonly is False
        assert rec_get.status is not None


def test_readonly_default_off_posts_flow():
    with TargetLab(behavior="vulnerable") as lab:
        http = RedTeamHTTP(guard=None)  # 預設非 read-only
        rec = http.request("POST", lab.base_url + "/v1/chat/completions",
                           json={"model": "x", "messages": [{"role": "user", "content": "hi"}]})
        assert rec.blocked_by_readonly is False
        assert rec.status == 200


def test_safe_methods_constant_locked():
    # RFC 9110 安全方法白名單 — 動它必須過程式審查
    assert SAFE_METHODS == frozenset({"GET", "HEAD", "OPTIONS"})
    assert "POST" not in SAFE_METHODS
    assert "DELETE" not in SAFE_METHODS


def test_readonly_llm_playbook_all_probes_blocked():
    """read-only 下 LLM 劇本(全 POST)必須如實標記 blocked,不得偽裝成護欄守住。"""
    pbs = load_playbooks(single=PB1)
    results: list = []
    with TargetLab(behavior="vulnerable") as lab:
        target = LLMTarget(ScopeGuard(None), lab.base_url, model="redteam-lab",
                           rate_qps=100, read_only=True)
        engine = PlaybookEngine(target, max_probes=10)
        results = engine.run(pbs[0])
    # 首個 POST 探測即被物理封鎖 → 引擎如實中斷(不偽裝成護欄守住)
    assert len(results) >= 1
    assert all(r.blocked_by_scope for r in results)
    assert all(not r.passed for r in results)
    # 標記必須寫明是 read-only 擋的(與 scope 擋可區分)
    assert any("read-only" in " ".join(r.steps) for r in results)


def test_scanner_bridge_readonly_rejects_active_scanners():
    from redteam.scanners import ScannerBridge

    b = ScannerBridge(read_only=True)
    with pytest.raises(ValueError, match="sqlmap"):
        b.sqlmap_runner("https://example.com")
    with pytest.raises(ValueError, match="full"):
        b.zap_api_scan("https://example.com", mode="full")
    with pytest.raises(ValueError, match="api"):
        b.zap_api_scan("https://example.com", mode="api", api_format="openapi")
    # baseline 與 nuclei(限速)允許
    job = b.zap_api_scan("https://example.com", mode="baseline")
    assert job.status == "queued"
    njob = b.nuclei_runner("https://example.com")
    assert "-rl" in njob.args  # read-only 降載


def test_scanner_bridge_default_allows_active():
    from redteam.scanners import ScannerBridge

    b = ScannerBridge()  # 非 read-only:全部允許
    b.sqlmap_runner("https://example.com")
    b.zap_api_scan("https://example.com", mode="full")
    njob = b.nuclei_runner("https://example.com")
    assert "-rl" not in njob.args


# ---------------------------------------------------------------------------
# 2. auth-header:注入與證據鏈脫敏
# ---------------------------------------------------------------------------

def test_llm_target_auth_header_sent_and_redacted():
    with TargetLab(behavior="vulnerable") as lab:
        target = LLMTarget(ScopeGuard(None), lab.base_url, model="redteam-lab",
                           rate_qps=100, auth_header="Authorization: Bearer supersecret-XYZ")
        resp = target.chat([{"role": "user", "content": "hi"}])
        assert resp.text  # 打到了靶場
        rec = target.http.records[-1]
        # 密鑰值不得出現在記錄任何欄位
        dumped = json.dumps(rec.request_headers or {}) + json.dumps(rec.response_headers or {})
        assert "supersecret-XYZ" not in dumped
        assert (rec.request_headers or {}).get("authorization") == "[REDACTED]"


def test_llm_target_auth_header_malformed_via_cli_style():
    # LLMTarget 端:無 ":" 的 header 整串當 name(value 空)→ 不炸
    target = LLMTarget(ScopeGuard(None), "http://127.0.0.1:1",
                       auth_header="X-No-Colon")
    # name 被整體接收(空 value),不拋例外即可
    assert any(k.lower() == "x-no-colon" for k in target.http.default_headers)


# ---------------------------------------------------------------------------
# 3. version_watch:版本比較 + GHSA 比對(monkeypatch 不打外網)
# ---------------------------------------------------------------------------

def test_version_compare_basic():
    assert version_lt("2.39.4", "2.39.6")
    assert not version_lt("2.39.6", "2.39.4")
    assert version_lt("1.9", "1.10")      # 數值比較非字典序
    assert version_lt("2.0.0-rc1", "2.0.1")


def test_version_in_range_ghsa_forms():
    assert version_in_range("2.39.4", "< 2.39.6")
    assert not version_in_range("2.39.6", "< 2.39.6")
    assert version_in_range("2.0.5", ">= 2.0.0, < 2.10.0")
    assert not version_in_range("2.10.0", ">= 2.0.0, < 2.10.0")
    assert version_in_range("1.0.0", "*")
    assert not version_in_range("1.0.0", "nonsense range here")  # 無法解析→保守 False


def test_detect_releases_n8n_sentry_pattern():
    html = ('<meta name="n8n:config:sentry" content='
            '"eyJyZWxlYXNlIjoibiBuOG5AMi4zOS40In0=">'
            '"release":"n8n@2.39.4","environment":"production"')
    assert detect_releases(html) == [("n8n", "2.39.4")]
    assert detect_releases("<html>nothing</html>") == []


def test_watch_matches_and_patched(monkeypatch):
    advisories = [{
        "cve_id": "CVE-2026-11111", "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "summary": "Expression Sandbox Escape", "severity": "high",
        "published_at": "2026-09-16T00:00:00Z",
        "vulnerabilities": [{
            "package": {"name": "n8n", "ecosystem": "npm"},
            "vulnerable_version_range": "< 2.39.6",
            "first_patched_version": "2.39.6",
        }],
    }]
    monkeypatch.setattr("redteam.version_watch.query_ghsa",
                        lambda *a, **k: advisories)
    wr = watch("n8n", "npm", "2.39.4")
    assert wr.passed and len(wr.matches) == 1
    assert wr.matches[0].first_patched == "2.39.6"
    assert wr.highest_severity == "high"
    assert wr.latest_advisory_date == "2026-09-16"  # 資料源新鮮度如實記錄
    # findings 轉換:帶修復版本、OWASP A06
    findings = convert_all({"version_watch": [wr]})
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "version_watch" and f.owasp == "A06"
    assert "2.39.6" in f.description and f.cvss_score > 0


def test_watch_error_degrades_gracefully(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network down")
    monkeypatch.setattr("redteam.version_watch.query_ghsa", boom)
    wr = watch("n8n", "npm", "2.39.4")
    assert not wr.passed and "GHSA 查詢失敗" in wr.error
    assert convert_all({"version_watch": [wr]}) == []  # 錯誤不產 finding 不 crash
