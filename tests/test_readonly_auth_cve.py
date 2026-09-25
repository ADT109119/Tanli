"""read-only 模式 / auth-header / version_watch 三項功能測試(2026-09-18 實務需求)。

全程 127.0.0.1(TargetLab)或純函數,無 Docker、無真實外網 GHSA 查詢。
"""

import json
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

from redteam.findings import convert_all
from redteam.interactor import RedTeamHTTP, SAFE_METHODS, ScopeGuard
from redteam.playbook import LLMTarget, PlaybookEngine, load_playbooks
from redteam.target_lab import TargetLab
from redteam.version_watch import detect_releases, version_in_range, version_lt, watch

REPO = Path(__file__).parent.parent
PB1 = str(REPO / "src" / "redteam" / "playbooks" / "llm" / "playbook_1.yaml")


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


# ---------------------------------------------------------------------------
# 3b. GHSA/NVD URL 構造回歸(實錄 2026-09-25 www.tph run 挖出的三個真 bug)
# ---------------------------------------------------------------------------

def test_query_ghsa_encodes_product_with_spaces(monkeypatch):
    """含空格產品名必須 URL encode，否則 InvalidURL 崩潰(www.tph 實錄)。"""
    import redteam.version_watch as vw
    captured = {}

    class FakeResp:
        def read(self):
            return b"[]"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["accept"] = req.get_header("Accept")
        return FakeResp()

    monkeypatch.setattr(vw.urllib.request, "urlopen", fake_urlopen)
    out = vw.query_ghsa("Apache HTTP Server", "generic")
    assert out == []
    assert " " not in captured["url"], f"URL 殘留未 encode 空格: {captured['url']}"
    assert "Apache%20HTTP%20Server" in captured["url"]
    assert captured["accept"] == "application/vnd.github+json"  # GHSA 仍用 vendor 型別


def test_query_ghsa_422_becomes_actionable_error(monkeypatch):
    """GHSA 對非法 ecosystem 回 422 → 轉成可操作訊息(建議改走 NVD)。"""
    import redteam.version_watch as vw

    def boom(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 422, "Unprocessable Entity", {}, None)

    monkeypatch.setattr(vw.urllib.request, "urlopen", boom)
    with pytest.raises(ValueError) as ei:
        vw.query_ghsa("Apache HTTP Server", "generic")
    assert "NVD" in str(ei.value)  # 指路正確降級方向
    wr = vw.watch("Apache HTTP Server", "generic", "2.4.58")  # 上層優雅降級不 crash
    assert not wr.passed and "GHSA 查詢失敗" in wr.error


def test_get_json_accept_per_host(monkeypatch):
    """NVD 對 vendor 型別 Accept 回 406(www.tph 實錄)——只有 github API
    發 vendor 型別,其餘源一律 application/json。"""
    import redteam.cve_lookup as cl
    captured = {}

    class FakeResp:
        def read(self):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        captured[req.full_url.split("/")[2]] = req.get_header("Accept")
        return FakeResp()

    monkeypatch.setattr(cl.urllib.request, "urlopen", fake_urlopen)
    cl._get_json("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-38477")
    cl._get_json("https://api.github.com/advisories?cve_id=CVE-2024-38477")
    cl._get_json("https://api.first.org/data/v1/epss?cve=CVE-2024-38477")
    assert captured["services.nvd.nist.gov"] == "application/json"
    assert captured["api.github.com"] == "application/vnd.github+json"
    assert captured["api.first.org"] == "application/json"


def test_get_json_host_strict_match_no_token_leak(monkeypatch):
    """agy review 實錘的安全隱患回歸:查詢關鍵字本身含 'api.github.com'
    (如 NVD keyword 查 github 相關 CVE)時,子字串判斷會把 GITHUB_TOKEN
    發給第三方源。hostname 嚴判後:不發 token、不發 vendor Accept。"""
    import redteam.cve_lookup as cl
    captured = {}

    class FakeResp:
        def read(self):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["accept"] = req.get_header("Accept")
        captured["auth"] = req.get_header("Authorization")
        return FakeResp()

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_sensitivetoken")
    monkeypatch.setattr(cl.urllib.request, "urlopen", fake_urlopen)
    # query string 內含 api.github.com 字樣的 NVD 查詢
    cl._get_json("https://services.nvd.nist.gov/rest/json/cves/2.0"
                 "?keywordSearch=api.github.com+vulnerability")
    assert captured["accept"] == "application/json"
    assert captured["auth"] is None, "GITHUB_TOKEN 外洩給非 github 源!"
    # 偽裝子域不騙過(hostname 嚴判)
    cl._get_json("https://api.github.com.evil.example/x")
    assert captured["accept"] == "application/json"
    assert captured["auth"] is None


def test_lookup_falls_back_to_nvd_on_illegal_ecosystem(monkeypatch):
    """生態系不合法(如 generic)→ GHSA+OSV 雙源皆死時自動降級 NVD keyword。"""
    import redteam.cve_lookup as cl

    def fake_ghsa(product, ecosystem):
        r = cl.LookupResult(query="x")
        r.error = f"GHSA 422:ecosystem={ecosystem!r} 不是合法組合"
        return r

    def fake_osv(package, ecosystem, version=None):
        r = cl.LookupResult(query="x")
        r.error = "OSV 查詢失敗(HTTPError): 400"
        return r

    nvd_called = {}

    def fake_nvd(*, keyword=None, cve_id=None):
        nvd_called["keyword"] = keyword
        r = cl.LookupResult(query=f"nvd-kw {keyword}")
        r.sources = ["nvd"]
        r.advisories = [cl.CveAdvisory(cve="CVE-2024-38477", source="nvd",
                                       severity="high", summary="test")]
        return r

    monkeypatch.setattr(cl, "ghsa_product", fake_ghsa)
    monkeypatch.setattr(cl, "osv_query", fake_osv)
    monkeypatch.setattr(cl, "nvd_search", fake_nvd)
    out = cl.lookup(product="Apache HTTP Server", ecosystem="generic")
    assert nvd_called.get("keyword") == "Apache HTTP Server"
    assert out.ok and out.sources == ["nvd"]
    assert "降級" in out.query  # 誠實標註降級來源
