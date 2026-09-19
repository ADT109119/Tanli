"""Smoke tests for the MVP skeleton."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from redteam.auth import ScopeEntry, ScopeGuard, ScopeStatement
from redteam.planner import CheckpointStore, build_default_plan
from redteam.report import redact


def test_scope_localhost_only_default():
    guard = ScopeGuard(None)
    assert guard.check("127.0.0.1", 8080, "/", "GET") is True
    assert guard.check("10.0.0.5", 80, "/", "GET") is False  # no credential => blocked


def test_scope_with_statement():
    stmt = ScopeStatement(
        authorized_by="ops",
        targets=[ScopeEntry(host="10.0.0.5", cidr="10.0.0.0/24", ports=[80], paths=["/api"], methods=["GET"])],
    )
    guard = ScopeGuard(stmt, public_key="x")
    assert guard.check("10.0.0.5", 80, "/api/login", "GET") is True
    assert guard.check("10.0.0.5", 443, "/api/login", "GET") is False  # port not in scope
    assert guard.check("10.0.0.9", 80, "/other", "GET") is False  # path outside /api


def test_build_default_plan():
    plan = build_default_plan("http://x", "web_service")
    assert len(plan.nodes) == 6
    assert plan.nodes[0].phase in ("recon", "fingerprint", "inject", "verify", "poc", "report")
    assert plan.next_pending().phase == "recon"


def test_checkpoint_roundtrip():
    store = CheckpointStore(dir_="/tmp/rt_checkpoint_test")
    plan = build_default_plan("http://x", "web_service")
    plan.nodes[0].status = "completed"
    path = store.save(plan, tag="t1")
    loaded = store.load(str(path))
    assert loaded.nodes[0].status == "completed"
    assert loaded.nodes[1].status == "not_started"


def test_redact_api_key():
    assert "****" in redact("sk-ABCD1234EFGH5678")
    assert redact("sk-ABCD1234EFGH5678", "full") == "sk-ABCD1234EFGH5678"


def test_report_owasp_aggregation():
    """P1: 報告按 OWASP 2021 聚合 tables + 未映射單獨列."""
    from redteam.report import Finding, ReportGenerator

    r = ReportGenerator("http://x", "web_service")
    r.add_finding(Finding("f-001", "web", "sqli", "high", "SQLi", "desc",
                          steps=["x"], owasp="A03"))
    r.add_finding(Finding("f-002", "web", "header", "medium", "No header", "desc",
                          steps=["x"], owasp="A05"))
    r.add_finding(Finding("f-003", "web", "generic", "info", "Tech detect", "desc",
                          steps=["x"], owasp=""))  # 未映射

    out = r.render()
    assert "## 5. OWASP 2021 覆蓋度聚合" in out
    assert "| A03 |" in out
    assert "| A05 |" in out
    assert "未映射" in out  # un-mapped bucket listed
    # 詳細表帶 OWASP 列
    assert "| f-001 | A03 |" in out
