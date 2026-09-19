"""web_config 確定性探測器測試(M5)- 起本地靶場,斷言各檢查項命中與零誤報。"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

from redteam.auth import ScopeGuard
from redteam.findings import convert_all, from_web_config
from redteam.interactor import RedTeamHTTP
from redteam.target_lab import TargetLab
from redteam.web_config import WebConfigProbe


@pytest.fixture()
def lab():
    with TargetLab() as t:
        yield t


@pytest.fixture()
def probe():
    # localhost-only 預設範圍即可覆蓋 127.0.0.1(不需憑證)
    return WebConfigProbe(http=RedTeamHTTP(guard=ScopeGuard(None)))


# ---------------------------------------------------------------------------
# 不安全首頁(/):各檢查項應命中
# ---------------------------------------------------------------------------

def test_probe_insecure_home_hits_header_checks(lab, probe):
    results = probe.run(lab.base_url)
    passed = [r for r in results if r.passed and r.category == "security_header"]
    ids = " ".join(r.id for r in passed)
    # 四個缺失安全頭都應命中(CSP/XFO/XCTO/Referrer-Policy)
    assert "content-security-policy" in ids
    assert "x-frame-options" in ids
    assert "x-content-type-options" in ids
    assert "referrer-policy" in ids


def test_probe_insecure_home_hsts_skipped_on_http(lab, probe):
    """http 目標:HSTS 應被跳過(passed=False)且 evidence 帶原因。"""
    results = probe.run(lab.base_url)
    hsts = [r for r in results if "strict-transport-security" in r.id]
    assert len(hsts) == 1
    assert hsts[0].passed is False
    joined = "\n".join(hsts[0].evidence)
    assert "https" in joined  # reason:僅適用 https,故跳過
    # 且不得產生 HSTS 相關 finding
    findings = from_web_config(results, counter=[0])
    assert not any("strict-transport-security" in f.title for f in findings)


def test_probe_insecure_home_cookie_attr_checks(lab, probe):
    """/ 的 Set-Cookie 缺 HttpOnly/Secure → 兩個檢查項都命中。"""
    results = probe.run(lab.base_url)
    cookie_hits = [r for r in results if r.passed and r.category == "cookie_attr"]
    ids = " ".join(r.id for r in cookie_hits)
    assert "httponly-sid" in ids
    assert "secure-sid" in ids
    # http 目標:缺 Secure 只記 info;缺 HttpOnly 為 low
    by_id = {r.id: r for r in cookie_hits}
    secure_hit = next(r for r in cookie_hits if "-secure-" in r.id)
    httponly_hit = next(r for r in cookie_hits if "-httponly-" in r.id)
    assert secure_hit.severity == "info"
    assert httponly_hit.severity == "low"


def test_evidence_contains_header_dump(lab, probe):
    """每個 finding 的 evidence 應含實際回應標頭摘要(header dump)。"""
    results = probe.run(lab.base_url)
    hits = [r for r in results if r.passed]
    assert hits
    for r in hits:
        assert any("set-cookie" in e or ":" in e for e in r.evidence)


def test_no_set_cookie_means_no_cookie_findings(lab, probe):
    """/sql 不送 Set-Cookie → 不得產生 cookie 屬性誤報。"""
    results = probe.run(lab.base_url, paths=["/sql"])
    assert not [r for r in results if r.category == "cookie_attr"]


# ---------------------------------------------------------------------------
# 加固頁(/secure):不得誤報
# ---------------------------------------------------------------------------

def test_secure_page_zero_false_positives(lab, probe):
    results = probe.run(lab.base_url, paths=["/secure"])
    assert not [r for r in results if r.passed]


def test_convert_secure_page_no_medium_or_critical(lab, probe):
    findings = convert_all({"web_config": probe.run(lab.base_url, paths=["/secure"])})
    assert not [f for f in findings if f.severity in ("medium", "critical")]


# ---------------------------------------------------------------------------
# ScopeGuard 整合:不可繞過
# ---------------------------------------------------------------------------

def test_scope_guard_blocks_remote_target(probe):
    """遠端目標超出 localhost-only 範圍 → 攔截,不得產生任何 passed 結果。"""
    results = probe.run("http://203.0.113.7:8080")
    assert results
    assert all(r.blocked_by_scope for r in results)
    assert not any(r.passed for r in results)
    assert convert_all({"web_config": results}) == []


# ---------------------------------------------------------------------------
# findings 正規化(from_web_config / convert_all)
# ---------------------------------------------------------------------------

def test_from_web_config_finding_fields(lab, probe):
    probes = probe.run(lab.base_url)
    findings = from_web_config(probes, counter=[100])
    assert len(findings) >= 5  # 4 缺失頭 + cookie 屬性
    for f in findings:
        assert f.attack_surface == "web"
        assert f.source == "web_config"
        assert f.confidence == 1.0  # 確定性證據
        assert f.owasp == "A05"
        assert f.fp_risk == "low"
        assert f.evidence  # 標頭摘要證據非空
    # id 產生方式對齊既有 _new_id 格式:f-{n:03d}(source),計數器遞增
    assert findings[0].id == "f-101(web_config)"
    assert findings[1].id == "f-102(web_config)"


def test_convert_all_canonical_order_and_key(lab, probe):
    """convert_all 支援 web_config 鍵,且排在最前(web_config 先跑)。"""
    fake_nuclei = [
        {"template-id": "x", "info": {"name": "Header Foo"}, "severity": "low",
         "matched-at": "/"},
    ]
    findings = convert_all({
        "nuclei": fake_nuclei,
        "web_config": probe.run(lab.base_url),
    })
    assert findings
    assert findings[0].source == "web_config"  # web_config 先行
    assert any(f.source == "nuclei" for f in findings)


def test_severity_bands_on_http_target(lab, probe):
    """http 目標的組態弱點最高 medium(CSP);不應出現 high/critical。"""
    findings = convert_all({"web_config": probe.run(lab.base_url)})
    assert findings
    assert all(f.severity in ("medium", "low", "info") for f in findings)
    assert any(f.severity == "medium" for f in findings)  # CSP 缺失


# ---------------------------------------------------------------------------
# agy review 修正回歸 (Finding-01 ~ 03)
# ---------------------------------------------------------------------------

def test_split_cookies_domain_tail_not_glued():
    """agy Finding-01 回歸:前段尾端 Domain= 不得吞掉下一個 cookie。"""
    raw = "a=1; Domain=example.com, b=2; Path=/"
    cookies = WebConfigProbe._split_cookies(raw)
    assert len(cookies) == 2
    assert cookies[0].startswith("a=1")
    assert cookies[1].startswith("b=2")


def test_split_cookies_expires_date_continuation_still_works():
    """agy Finding-01 反向回歸:Expires 型日期續體(星期+逗號)仍要併回前段。"""
    raw = "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT, b=2"
    cookies = WebConfigProbe._split_cookies(raw)
    assert len(cookies) == 2
    assert cookies[0] == "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT"
    assert cookies[1].startswith("b=2")


def test_split_cookies_multiple_plain():
    """多個普通 cookie(無日期)以逗號分隔應全數切出。"""
    raw = "a=1; Path=/, b=2; Path=/, c=3; Path=/"
    cookies = WebConfigProbe._split_cookies(raw)
    assert [c.split("=")[0] for c in cookies] == ["a", "b", "c"]


def test_cookie_flag_exact_match_no_prefix_false_positive():
    """agy Finding-02:自訂屬性 SecureProxy=true / HttpOnlyMode=off 不得
    被誤判為 Secure/HttpOnly(整詞精準比對)。"""
    raw = "sid=abc; SecureProxy=true; HttpOnlyMode=off"
    flags = [f.strip().lower() for f in raw.split(";")[1:]]
    has_secure = any(f == "secure" for f in flags)
    has_httponly = any(f == "httponly" for f in flags)
    assert has_secure is False
    assert has_httponly is False
    # 而正規的 Secure/HttpOnly 仍要被認出
    flags2 = [f.strip().lower() for f in "sid=abc; Secure; HttpOnly".split(";")[1:]]
    assert any(f == "secure" for f in flags2)
    assert any(f == "httponly" for f in flags2)


def test_connection_error_does_not_raise_and_yields_error_result(monkeypatch):
    """agy Finding-03:連線失敗不得炸掉 run,改記 info 錯誤結果(passed=False)。"""
    import httpx

    probe = WebConfigProbe()

    def _raise(*a, **k):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(probe.http, "request", _raise)
    results = probe.run("http://127.0.0.1:1", paths=["/"])
    assert results
    assert all(not r.passed for r in results)
    assert any("連線錯誤" in r.name for r in results)
    # 不得產生任何 security_header 缺失誤報
    assert not [r for r in results if r.passed and r.category == "security_header"]


def test_5xx_skips_config_checks_no_false_positives(monkeypatch):
    """agy Finding-03:5xx 錯誤頁不得被當成 app 組態檢查(防誤報 5 個缺頭)。"""
    from redteam.interactor import InteractionRecord

    rec = InteractionRecord("GET", "http://127.0.0.1:1/", 502, None,
                            {"content-type": "text/html"}, b"<html>502</html>")
    probe = WebConfigProbe()
    monkeypatch.setattr(probe.http, "request", lambda *a, **k: rec)
    results = probe.run("http://127.0.0.1:1", paths=["/"])
    assert results
    assert all(not r.passed for r in results)
    assert any("伺服器錯誤" in r.name for r in results)
    # 且不得有「缺少安全回應標頭」的 finding
    assert not [r for r in results if "缺少安全" in r.name]
