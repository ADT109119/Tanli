"""Regression tests for dual-agent review fixes (opencode + agy + manual, 2026-08).

Covers: scope-block dead code, httpx timeout wiring, CRL revocation,
scope window fail-closed, config deep-merge, docker network policy,
nuclei args, sqlmap tail truncation, --full/--resume CLI guards.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import httpx

from redteam.auth import (
    ScopeEntry, ScopeGuard, ScopeStatement,
    credential_kid, sign_credential, verify_credential,
)
from redteam.config import Config
from redteam.findings import from_sqlmap
from redteam.interactor import RedTeamHTTP
from redteam.playbook import LLMTarget
from redteam.scanners import HARDENING, ScannerBridge, target_is_local


# ---------------------------------------------------------------------------
# High #1: scope-block returns a blocked record (no exception)
# ---------------------------------------------------------------------------

def test_scope_blocked_returns_record_not_exception():
    guard = ScopeGuard(None)  # localhost-only
    http = RedTeamHTTP(guard=guard)
    # Remote host is outside scope: must RETURN blocked record, not raise.
    rec = http.request("GET", "http://10.0.0.5:8080/x")
    assert rec.blocked_by_scope is True
    assert rec.status is None
    # localhost still passes (no real request sent in this test? it would try;
    # so only assert the blocked path here).


def test_llm_target_chat_scope_blocked():
    """LLMTarget.chat on an out-of-scope endpoint yields scope_blocked."""
    import redteam.playbook as pb

    guard = ScopeGuard(None)
    target = LLMTarget(guard=guard, base_url="http://10.0.0.5:8080/v1")
    # Monkeypatch _endpoint to a concrete URL outside scope; chat must not
    # touch the network and must report scope_blocked.
    resp = target.chat([{"role": "user", "content": "hi"}])
    assert resp.finish_reason == "scope_blocked"
    assert resp.text == ""


def test_llm_target_chat_http_error_is_probe_level():
    """A network error inside chat() must not raise (playbook keeps going)."""
    guard = ScopeGuard(None)
    target = LLMTarget(guard=guard, base_url="http://127.0.0.1:1/v1")  # closed port

    def _raise(*a, **k):
        raise httpx.ConnectError("boom")

    target.http.request = _raise
    resp = target.chat([{"role": "user", "content": "hi"}])
    assert resp.finish_reason is not None and resp.finish_reason.startswith("request_error")


# ---------------------------------------------------------------------------
# High #3: httpx timeout actually wired
# ---------------------------------------------------------------------------

def test_httpx_timeout_wired():
    http = RedTeamHTTP(timeout=7.5)
    # httpx.Client stores it in client._timeout
    assert http.client._timeout.read == 7.5


def test_llm_target_passes_timeout():
    guard = ScopeGuard(None)
    target = LLMTarget(guard=guard, base_url="http://127.0.0.1:9/v1", timeout=9.0)
    assert target.http.client._timeout.read == 9.0


# ---------------------------------------------------------------------------
# High #2: docker network policy + hardening
# ---------------------------------------------------------------------------

def test_target_is_local():
    assert target_is_local("http://127.0.0.1:8080/x")
    assert target_is_local("http://localhost:9000/")
    assert target_is_local("http://[::1]:80/")
    assert target_is_local("127.0.0.1:8080")
    assert not target_is_local("http://10.0.0.5:8080/")
    assert not target_is_local("https://example.com/")


def test_remote_job_requires_network(monkeypatch):
    """Remote target without --network => job fails with a clear message,
    and NO docker process is spawned."""
    spawned = []

    async def fake_create_subprocess_exec(*args, **kwargs):
        spawned.append(args)
        raise AssertionError("docker must not be spawned for remote w/o network")

    import asyncio
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    bridge = ScannerBridge(network=None, timeout=5)
    job = bridge.zap_api_scan("http://10.0.0.5:8080/")
    assert job.target == "http://10.0.0.5:8080/"
    asyncio.run(bridge.start(job))
    assert job.status == "failed"
    assert "explicit egress network" in job.stderr
    assert spawned == []


def test_hardening_flags_present():
    assert "--cap-drop" in HARDENING and "ALL" in HARDENING
    assert "no-new-privileges:true" in HARDENING


# ---------------------------------------------------------------------------
# Medium #4/#5: nuclei args
# ---------------------------------------------------------------------------

def test_nuclei_no_dangling_update_template_dir():
    bridge = ScannerBridge()
    job = bridge.nuclei_runner("http://127.0.0.1:8080", templates="/tmp/t.yaml")
    assert "--update-template-dir" not in job.args
    assert "-t" in job.args and "/tmp/t.yaml" in job.args


# ---------------------------------------------------------------------------
# Medium #7: scope window fail-closed
# ---------------------------------------------------------------------------

def test_scope_window_parse_failure_fails_closed():
    entry = ScopeEntry(host="10.0.0.5", window="not-a-date/also-not")
    assert entry._in_window() is False
    assert entry.allows("10.0.0.5", 80, "/", "GET") is False


def test_scope_window_valid_range_still_works():
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    w = f"{(now - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')}/{(now + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')}"
    entry = ScopeEntry(host="10.0.0.5", window=w)
    assert entry._in_window() is True
    past = f"{(now - timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ')}/{(now - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')}"
    assert ScopeEntry(host="10.0.0.5", window=past)._in_window() is False


# ---------------------------------------------------------------------------
# Medium #8: CRL revocation
# ---------------------------------------------------------------------------

def test_crl_revoked_credential(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    key = Ed25519PrivateKey.generate()
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    stmt = ScopeStatement(
        authorized_by="ops",
        targets=[ScopeEntry(host="10.0.0.5", ports=[80])],
    )
    token = sign_credential(stmt, priv_pem, kid="redteam-42")

    # Not revoked: authorized
    monkeypatch.delenv("REDTEAM_REVOKED_KIDS", raising=False)
    s2, kid = verify_credential(token, pub_pem)
    guard = ScopeGuard(s2, pub_pem, credential_kid=kid)
    assert guard.is_authorized() is True
    assert guard.check("10.0.0.5", 80, "/", "GET") is True

    # Revoked: treated as unauthenticated -> localhost-only
    monkeypatch.setenv("REDTEAM_REVOKED_KIDS", "redteam-42")
    s3, kid3 = verify_credential(token, pub_pem)
    guard2 = ScopeGuard(s3, pub_pem, credential_kid=kid3)
    assert guard2.is_revoked() is True
    assert guard2.is_authorized() is False
    assert guard2.check("10.0.0.5", 80, "/", "GET") is False  # remote denied
    assert guard2.check("127.0.0.1", 8080, "/", "GET") is True  # localhost ok


def test_credential_kid_extracted_from_header():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    key = Ed25519PrivateKey.generate()
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    stmt = ScopeStatement(authorized_by="ops", targets=[ScopeEntry(host="10.0.0.5")])
    token = sign_credential(stmt, priv_pem, kid="kid-xyz")
    assert credential_kid(token) == "kid-xyz"


# ---------------------------------------------------------------------------
# Medium #10: config deep merge
# ---------------------------------------------------------------------------

def test_config_deep_merge_keeps_sibling_keys(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("llm:\n  judge:\n    base_url: https://example.local/v1\n")
    cfg = Config.load(str(p))
    # base_url overridden, model default preserved (deep merge)
    assert cfg.llm["judge"]["base_url"] == "https://example.local/v1"
    assert cfg.llm["judge"]["model"] == "gpt-4o"
    # unrelated default untouched
    assert cfg.runtime["job_timeout"] == 1800


# ---------------------------------------------------------------------------
# Low: sqlmap tail truncation + precedence
# ---------------------------------------------------------------------------

def test_from_sqlmap_tail_keeps_verdict():
    verdict = " [SQL] GET: param id - 1 injection point(s) found, is vulnerable"
    long_prefix = "x" * 5000
    raw = long_prefix + verdict
    out = from_sqlmap({"raw": raw[-4000:]}, [0])
    assert len(out) == 1  # verdict survived the tail truncation


def test_from_sqlmap_precedence():
    # "not injectable" must not be counted as a positive
    assert from_sqlmap({"raw": "all tested parameters are not injectable"}, [0]) == []
    assert len(from_sqlmap({"raw": "id is vulnerable to SQL injection"}, [0])) == 1
