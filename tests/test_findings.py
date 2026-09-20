"""Tests for scanner-result -> Finding conversion and LLM judge integration."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from redteam.findings import (
    convert_all,
    from_nuclei,
    from_sqlmap,
    from_zap,
    map_nuclei_to_owasp,
    map_zap_to_owasp,
)
from redteam.judge import LLMJudge, RegexJudge


def test_from_nuclei():
    counter = [0]
    fs = from_nuclei(
        [
            {
                "info": {"name": "SQL Injection", "severity": "critical"},
                "template-id": "t-1",
                "matched-at": "http://x/?id=1",
            },
            {
                "info": {"name": "Generic Detection", "severity": "info"},
                "template-id": "t-2",
                "matched-at": "http://x/",
            },
        ],
        counter,
    )
    assert len(fs) == 2
    assert fs[0].severity == "critical"  # reads nested info.severity (nuclei jsonl)
    assert fs[0].source == "nuclei"
    assert fs[0].poc is not None and fs[0].poc.startswith("# re-run")
    assert fs[1].severity == "info"


def test_from_sqlmap():
    counter = [0]
    # Positive: parameter is vulnerable
    fs = from_sqlmap({"raw": "GET param 'id' is vulnerable (boolean-based blind)"}, counter)
    assert len(fs) == 1
    assert fs[0].category == "sqli"
    assert fs[0].severity == "high"

    # Negative: sqlmap explicitly says not injectable -> no finding (no false positive)
    neg = (
        "[INFO] testing if GET parameter 'id' is 'Generic UNION query' injectable\n"
        "[INFO] GET parameter 'id' is not injectable\n"
        "[WARNING] all tested parameters do not appear to be injectable"
    )
    fs2 = from_sqlmap({"raw": neg}, counter)
    assert fs2 == []  # critical: must NOT emit a finding for a clean sqlmap run


def test_from_zap():
    counter = [0]
    alert = "WARN-NEW: Missing Anti-clickjacking Header [10020] x 2\n\thttp://x/"
    zap = {"alerts": [alert], "warn": 1, "fail": 0}
    fs = from_zap(zap, counter)
    assert len(fs) == 1
    assert fs[0].category == "security_header"
    assert fs[0].severity == "medium"
    assert fs[0].title.startswith("ZAP WARN-NEW")


def test_convert_all_ordering():
    counter = [0]
    results = {
        "nuclei": [{"info": {"name": "A"}, "severity": "low", "matched-at": "http://x/"}],
        "zap": {"alerts": ["WARN-NEW: X [10020] x 1"], "warn": 1, "fail": 0},
    }
    fs = convert_all(results, counter)
    assert fs[0].source == "nuclei"
    assert fs[1].source == "zap"


def test_regex_judge_sqli():
    j = RegexJudge()
    r = j.determine("You have an error in your SQL syntax near '1'", "sqli")
    assert r.confident
    assert r.confidence > 0.5


def test_llm_judge_verdict_norm():
    j = LLMJudge({})
    assert j.verdict("CONFIRMED: decisive evidence") == "confirmed"
    assert j.verdict("REFUTED: just a echo") == "refuted"
    assert j.verdict("Maybe?") == "uncertain"
    assert j.verdict("LLM_ERROR: timeout") == "uncertain"
    assert j.verdict(None) == "uncertain"


def test_llm_judge_no_key_returns_none():
    import os

    # Ensure no judge API key is set
    old = {k: os.environ.get(k) for k in ("REDTEAM_JUDGE_API_KEY", "OPENAI_API_KEY")}
    for k in old:
        os.environ.pop(k, None)
    try:
        j = LLMJudge({})
        assert j.confirm("evidence", "suspect") is None  # graceful no-LLM
    finally:
        for k, v in old.items():
            if v:
                os.environ[k] = v


class _FakeCompletions:
    def create(self, **kw):
        return type("R", (), {"choices": [type("C", (), {"message": type("M", (), {"content": "CONFIRMED: sqlmap found injectable param"})()})()]})()


class _FakeChat:
    completions = _FakeCompletions()


class _FakeClient:
    chat = _FakeChat()


def test_llm_judge_mock_endpoint(monkeypatch):
    """Simulate an OpenAI-compatible endpoint returning CONFIRMED."""
    import os

    os.environ["REDTEAM_JUDGE_BASE_URL"] = "http://fake/v1"
    os.environ["REDTEAM_JUDGE_API_KEY"] = "test"
    try:
        j = LLMJudge({"model": "test-model"})
        monkeypatch.setattr(j, "_client", _FakeClient())
        j._model = "test-model"
        text = j.confirm("evidence here", "SQL Injection")
        assert text is not None
        assert j.verdict(text) == "confirmed"
    finally:
        os.environ.pop("REDTEAM_JUDGE_API_KEY", None)
        os.environ.pop("REDTEAM_JUDGE_BASE_URL", None)


def test_redact():
    from redteam.report import redact

    # API key: sk- prefix keeps first4+last4
    out = redact("sk-abcdefghijklmnop")
    assert "sk-abcd****mnop" in out
    assert "sk-abcdefghijklmnop" not in out

    # JWT: masked, keep header prefix + last4 sig only
    jwt = "eyJ0eXAiOiJKV1Q.eyJzdWIiOjEyMzQ1ZGVmLWlzY29u.abcdefgh1234"
    out2 = redact(f"token={jwt}")
    assert "eyJ0eXA.****.abcd" in out2
    assert "eyJzdWIiOjEyMzQ1ZGVmLWlzY29u" not in out2  # full payload masked
    assert "abcdefgh" not in out2  # signature body masked

    # Bearer token
    assert redact("Authorization: Bearer abc12345XYZ789") == "Authorization: Bearer ****"

    # Cookie value masked
    assert redact("Cookie: session=abc123xyz") == "Cookie: session=****"

    # full mode does nothing
    assert redact("sk-abcdefghijklmnop", mode="full") == "sk-abcdefghijklmnop"


def test_config_no_global_mutation(tmp_path):
    """Config.load must not leak user values into the module-level DEFAULT_CONFIG."""
    from redteam.config import DEFAULT_CONFIG, Config

    c = tmp_path / "c.yaml"
    c.write_text("llm:\n  judge:\n    model: MY_CUSTOM_MODEL\n")
    cfg1 = Config.load(str(c))
    assert cfg1.llm["judge"]["model"] == "MY_CUSTOM_MODEL"
    # A second load without the override must NOT see the mutated value
    cfg2 = Config.load()
    assert cfg2.llm["judge"].get("model", "gpt-4o") != "MY_CUSTOM_MODEL"


def test_rewrite_localhost_preserves_scheme():
    from redteam.scanners import ScannerBridge

    assert ScannerBridge._rewrite_localhost("http://127.0.0.1:8000/api") == "http://host.docker.internal:8000/api"
    assert ScannerBridge._rewrite_localhost("https://127.0.0.1:8443/api") == "https://host.docker.internal:8443/api"
    assert ScannerBridge._rewrite_localhost("http://localhost:8080") == "http://host.docker.internal:8080"
    assert ScannerBridge._rewrite_localhost("https://example.com") == "https://example.com"


def test_scope_guard_scanner_path(tmp_path):
    """ScopeGuard blocks non-localhost scanner targets without a credential."""
    from redteam.auth import ScopeGuard

    guard = ScopeGuard(None)  # unauthenticated -> localhost-only
    assert guard.check("127.0.0.1", 80, "/", "GET") is True
    assert guard.check("10.0.0.5", 80, "/", "GET") is False
    assert guard.check("localhost.evil.com", 80, "/", "GET") is False


# ---------------------------------------------------------------------------
# P1: OWASP 類別映射層
# ---------------------------------------------------------------------------

def test_map_nuclei_tags_to_owasp():
    # sqli tag -> A03
    assert map_nuclei_to_owasp({"tags": ["sqli", "rce"], "name": "SQL Injection"}) == "A03"
    # xss tag -> A03
    assert map_nuclei_to_owasp({"tags": ["xss"], "name": "Reflected XSS"}) == "A03"
    # idor tag -> A01
    assert map_nuclei_to_owasp({"tags": ["idor"], "name": "IDOR test"}) == "A01"
    # default-login -> A07 (auth/credential)
    assert map_nuclei_to_owasp({"tags": ["default-login"], "name": "Default login"}) == "A07"
    # ssrf tag -> A10
    assert map_nuclei_to_owasp({"tags": ["ssrf"], "name": "SSRF probe"}) == "A10"
    # cve tag -> A06
    assert map_nuclei_to_owasp({"tags": ["cve"], "name": "CVE-2023-123"}) == "A06"


def test_map_nuclei_keyword_fallback():
    # No tags -> keyword fallback on name
    assert map_nuclei_to_owasp({"name": "SQL Injection Detection"}) == "A03"
    assert map_nuclei_to_owasp({"name": "CVE-2023-456 known-vuln"}) == "A06"
    # Unknown name, no tags -> "" (未映射), NOT forced into A05
    assert map_nuclei_to_owasp({"name": "Generic Tech Detect"}) == ""


def test_map_zap_alert_to_owasp():
    assert map_zap_to_owasp("10020") == "A05"  # anti-clickjacking header
    assert map_zap_to_owasp("10036") == "A02"  # info disclosure
    assert map_zap_to_owasp("40012") == "A03"  # SQLi active
    assert map_zap_to_owasp("40046") == "A10"  # SSRF
    assert map_zap_to_owasp("20019") == "A01"  # Open Redirect
    assert map_zap_to_owasp("90035") == "A03"  # SSTI
    assert map_zap_to_owasp("10202") == "A01"  # CSRF
    assert map_zap_to_owasp("99999") == ""     # unknown -> 未映射


def test_from_nuclei_owasp_field():
    counter = [0]
    fs = from_nuclei(
        [{"info": {"name": "SQL Injection", "severity": "critical", "tags": ["sqli"]},
          "template-id": "t-1", "matched-at": "http://x/?id=1"}],
        counter,
    )
    assert len(fs) == 1
    assert fs[0].owasp == "A03"


def test_from_nuclei_extracted_results_to_extracted_field():
    # nuclei extractor 抓到的真實資料必須進 Finding.extracted(list 原貌),
    # 供 ReportGenerator.attach_exfil 登錄進報告 §3(exfil 閉環)
    counter = [0]
    fs = from_nuclei(
        [{"info": {"name": "Exposed .env", "severity": "high",
                   "tags": ["exposure", "config"]},
          "template-id": "t-env", "matched-at": "http://x/.env",
          "extracted-results": ["DB_PASSWORD=hunter2", "AWS_SECRET=abc123"]}],
        counter,
    )
    assert fs[0].extracted == ["DB_PASSWORD=hunter2", "AWS_SECRET=abc123"]
    # evidence 仍為拼接字串(judge 二審用,向後兼容)
    assert "DB_PASSWORD=hunter2" in fs[0].evidence
    assert "AWS_SECRET=abc123" in fs[0].evidence


def test_from_nuclei_extracted_results_string_or_absent():
    # extracted-results 可能是字串(jsonl 變體)或缺失,兩者都不得 crash
    counter = [0]
    fs = from_nuclei(
        [{"info": {"name": "t", "severity": "info"}, "template-id": "x",
          "matched-at": "http://x/", "extracted-results": "solo-value"},
         {"info": {"name": "t2", "severity": "info"}, "template-id": "y",
          "matched-at": "http://x/"}],
        counter,
    )
    assert fs[0].extracted == ["solo-value"]
    assert fs[1].extracted == []
    assert fs[1].evidence == ""


def test_from_sqlmap_owasp_field():
    counter = [0]
    fs = from_sqlmap({"raw": "GET param 'id' is vulnerable (boolean-based blind)"}, counter)
    assert fs[0].owasp == "A03"


def test_from_zap_owasp_field_and_tags():
    counter = [0]
    alert = "WARN-NEW: Missing Anti-clickjacking Header [10020] x 2\n\thttp://x/"
    zap = {"alerts": [alert], "warn": 1, "fail": 0, "mode": "baseline"}
    fs = from_zap(zap, counter)
    assert fs[0].owasp == "A05"  # fallback alert-id map

    # With ZAP official tags (from zap-report.json) — prefer tags over id map
    zap_tags = {"alerts": [alert], "warn": 1, "fail": 0, "mode": "full",
                "tags_by_id": {"10020": ["OWASP Top Ten 2021", "A07"]}}
    fs2 = from_zap(zap_tags, counter)
    assert fs2[0].owasp == "A07"  # official tags take priority


def test_from_zap_full_mode_description():
    counter = [0]
    alert = "FAIL-NEW: SQL Injection [40012] x 1\n\thttp://x/?id=1"
    zap = {"alerts": [alert], "warn": 0, "fail": 1, "mode": "full"}
    fs = from_zap(zap, counter)
    assert fs[0].owasp == "A03"
    assert "full" in fs[0].steps[0]
    assert fs[0].severity == "high"  # FAIL-NEW
