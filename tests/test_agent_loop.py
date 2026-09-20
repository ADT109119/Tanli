"""自主 agent loop 與 cve_lookup 測試(離線 FakeBrain + 網路可跳過)。"""

import json
import os

import pytest

from redteam.agent import AgentTools, AgentRunResult, run_agent
from redteam.auth import ScopeGuard
from redteam.interactor import RedTeamHTTP


class FakeBrain:
    """腳本化 brain:依序吐出預設 tool call,最後 finish。"""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def step(self, messages):
        item = self.script.pop(0) if self.script else {"final": "done"}
        self.calls.append(item)
        item = dict(item)  # type: ignore[var-annotated]
        if "tokens" not in item:
            item["tokens"] = 100  # type: ignore[assignment]
        return item


@pytest.fixture
def tools():
    guard = ScopeGuard(None)  # localhost-only
    http = RedTeamHTTP(guard=guard, read_only=True)
    return AgentTools(http, "http://127.0.0.1:9/", docker_bridge=None)


def test_tool_schemas_wellformed():
    names = [s["name"] for s in AgentTools.SCHEMAS]
    for expected in ("http_request", "fingerprint", "cve_lookup", "version_watch",
                     "nuclei_cve_probe", "add_finding", "finish"):
        assert expected in names
    for s in AgentTools.SCHEMAS:
        assert json.dumps(s)  # 必須可序列化(function calling 要求)


def test_loop_records_findings_and_finishes(tools):
    brain = FakeBrain([
        {"thought": "先指紋", "tool": "fingerprint", "args": {}},
        {"thought": "查全部 CVE", "tool": "cve_lookup",
         "args": {"product": "django", "ecosystem": "pip"}},
        {"thought": "記一筆", "tool": "add_finding",
         "args": {"title": "test finding", "severity": "high",
                  "description": "d", "evidence": "e", "cve": "CVE-2026-00001"}},
        {"thought": "完成", "tool": "finish", "args": {"summary": "all good"}},
    ])
    res = run_agent(tools, brain, goal="test", max_steps=10)
    assert isinstance(res, AgentRunResult)
    assert res.finished and res.summary == "all good"
    assert len(res.findings) == 1
    assert res.findings[0].cve == "CVE-2026-00001"
    assert res.steps >= 4
    # 每步都有 transcript(可稽核)
    assert all("tool" in t for t in res.transcript)


def test_add_finding_exfiltrated_data_plumbing(tools):
    """add_finding.exfiltrated_data → AgentFinding.exfiltrated(exfil 閉環第一段)。

    清洗規則:字串容錯包成 list、單筆截 500 字、總量截 10 筆、空值丟棄。
    """
    brain = FakeBrain([
        {"thought": "拖到資料", "tool": "add_finding",
         "args": {"title": "leak", "severity": "critical",
                  "description": "d", "evidence": "e",
                  "exfiltrated_data": ["secret-line-1", "secret-line-2"]}},
        {"thought": "字串變體+超長", "tool": "add_finding",
         "args": {"title": "leak2", "severity": "high",
                  "description": "d", "evidence": "e",
                  "exfiltrated_data": "solo-string-" + "x" * 600}},
        {"thought": "未登錄", "tool": "add_finding",
         "args": {"title": "clean", "severity": "low",
                  "description": "d", "evidence": "e"}},
        {"thought": "done", "tool": "finish", "args": {"summary": "ok"}},
    ])
    res = run_agent(tools, brain, goal="test", max_steps=10)
    assert res.findings[0].exfiltrated == ["secret-line-1", "secret-line-2"]
    # 字串容錯 + 500 字截斷
    assert len(res.findings[1].exfiltrated) == 1
    assert len(res.findings[1].exfiltrated[0]) == 500
    # 未登錄 → 空清單(§3 渲染走「未登錄」明示路徑)
    assert res.findings[2].exfiltrated == []


def test_add_finding_exfiltrated_data_over_cap(tools):
    """超過 10 筆只留前 10 筆(防 bulk dump 灌進報告)。"""
    brain = FakeBrain([
        {"thought": "dump", "tool": "add_finding",
         "args": {"title": "bulk", "severity": "high", "description": "d",
                  "evidence": "e",
                  "exfiltrated_data": [f"row-{i}" for i in range(25)]}},
        {"thought": "done", "tool": "finish", "args": {"summary": "ok"}},
    ])
    res = run_agent(tools, brain, goal="test", max_steps=10)
    assert len(res.findings[0].exfiltrated) == 10
    assert res.findings[0].exfiltrated[0] == "row-0"


def test_agent_report_bridging_exfil_to_section3(tools):
    """閉環端到端(離線):add_finding 登錄 → Finding.extracted →
    attach_exfil → 報告 §3 逐字出現且 sk- 金鑰自動遮罩。"""
    from redteam.findings import Finding as SFinding
    from redteam.report import ReportGenerator

    brain = FakeBrain([
        {"thought": "拿到假金鑰", "tool": "add_finding",
         "args": {"title": "env leak", "severity": "critical",
                  "description": "d", "evidence": "GET /.env 200",
                  "exfiltrated_data": [
                      'API_KEY="sk-live0000000000000000000000abcd1234"',
                      "canary=REDTEAM_EXFIL_CANARY_9f3a"]}},
        {"thought": "done", "tool": "finish", "args": {"summary": "ok"}},
    ])
    res = run_agent(tools, brain, goal="test", max_steps=10)
    # 模擬 cli agent 命令的報告橋接(同構代碼,不依賴 Typer runner)
    report = ReportGenerator("http://127.0.0.1:9/", "hybrid")
    for i, f in enumerate(res.findings, 1):
        report.add_finding(SFinding(
            id=f"agent-{i:02d}", attack_surface="hybrid", category=f.category,
            severity=f.severity, title=f.title, description=f.description,
            steps=["autonomous agent loop"], poc=f.evidence[:1500] or None,
            confidence=f.confidence, evidence=f.evidence[:2000], source="agent",
            extracted=list(getattr(f, "exfiltrated", None) or []),
        ))
    n = report.attach_exfil()
    assert n == 2
    sec3 = report.render().split("## 3.", 1)[1].split("## 4.", 1)[0]
    assert "REDTEAM_EXFIL_CANARY_9f3a" in sec3
    assert "sk-live****1234" in sec3
    assert "0000000000000000000000" not in sec3


def test_readonly_blocks_post(tools):
    brain = FakeBrain([
        {"thought": "試著 POST", "tool": "http_request",
         "args": {"method": "POST", "url": "http://127.0.0.1:9/x", "body": "x=1"}},
        {"final": "done"},
    ])
    res = run_agent(tools, brain, goal="t", max_steps=5)
    blocked = res.transcript[0]
    assert blocked["tool"] == "http_request"
    # read-only 物理封鎖:工具層如實回報 blocked(工具 ok=False)
    assert "BLOCKED" in blocked["note"] or "blocked" in blocked["note"].lower()


def test_scope_guard_blocks_out_of_scope(tools):
    brain = FakeBrain([
        {"thought": "打外部", "tool": "http_request",
         "args": {"method": "GET", "url": "http://9.9.9.9:81/evil"}},
        {"final": "done"},
    ])
    res = run_agent(tools, brain, goal="t", max_steps=5)
    assert "ScopeGuard" in res.transcript[0]["note"]


def test_probe_budget_enforced(tools):
    tools.max_probes = 2
    brain = FakeBrain([
        {"thought": "probe", "tool": "http_request",
         "args": {"method": "GET", "url": "http://127.0.0.1:9/"}}
        for _ in range(5)
    ] + [{"final": "end"}])
    res = run_agent(tools, brain, goal="t", max_steps=10)
    # 第 3 發起必須被預算擋下(工具層 ok=False,不離網)
    blocked = [t for t in res.transcript if "budget" in t["note"].lower()]
    assert blocked, "probe budget 未強制"


def test_identical_get_is_cached_without_budget():
    # 用真實本地靶場:成功回應才會進快取(錯誤不該被快取)
    from redteam.target_lab import TargetLab
    with TargetLab(behavior="vulnerable") as lab:
        http = RedTeamHTTP(guard=ScopeGuard(None), read_only=True)
        tools = AgentTools(http, lab.base_url, docker_bridge=None)
        tools.max_probes = 10
        brain = FakeBrain([
            {"thought": "get", "tool": "http_request",
             "args": {"method": "GET", "url": f"{lab.base_url}/x"}},
            {"thought": "重複 get", "tool": "http_request",
             "args": {"method": "GET", "url": f"{lab.base_url}/x"}},
            {"final": "done"},
        ])
        res = run_agent(tools, brain, goal="t", max_steps=5)
        # 同 GET 第二次必須走快取(注記 cached)且不重複計價
        assert "cached" in res.transcript[1]["note"].lower()
        assert res.probes == 1


def test_max_steps_terminates(tools):
    brain = FakeBrain([
        {"thought": "loop", "tool": "fingerprint", "args": {}} for _ in range(50)
    ])
    res = run_agent(tools, brain, goal="t", max_steps=3)
    assert res.steps == 3
    assert "max_steps" in res.summary or "上限" in res.summary


def test_unknown_tool_reported(tools):
    brain = FakeBrain([
        {"thought": "x", "tool": "rm_rf", "args": {}},
        {"final": "done"},
    ])
    res = run_agent(tools, brain, goal="t", max_steps=5)
    assert res.transcript[0]["ok"] is False
    assert "unknown tool" in res.transcript[0]["note"]


def test_nuclei_probe_requires_docker(tools):
    brain = FakeBrain([
        {"thought": "試 CVE", "tool": "nuclei_cve_probe",
         "args": {"cve_id": "CVE-2025-55182"}},
        {"final": "done"},
    ])
    res = run_agent(tools, brain, goal="t", max_steps=5)
    t = res.transcript[0]
    assert t["ok"] is False  # docker=None → 如實回報不可用,不假裝成功
    assert "Docker" in t["note"]


def test_nuclei_probe_rejects_bad_tag(tools):
    brain = FakeBrain([
        {"thought": "x", "tool": "nuclei_cve_probe",
         "args": {"cve_id": "not-a-cve; rm -rf /"}},
        {"final": "done"},
    ])
    res = run_agent(tools, brain, goal="t", max_steps=5)
    assert res.transcript[0]["ok"] is False


# ---- cve_lookup(網路測試:無網路環境自動跳過) ----

def _net():
    import socket
    try:
        socket.create_connection(("api.github.com", 443), timeout=3).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _net(), reason="無外部網路")
def test_cve_lookup_by_id():
    from redteam.cve_lookup import lookup
    r = lookup(cve_id="CVE-2025-55182")
    assert r.ok, r.error
    assert any(a.cve == "CVE-2025-55182" for a in r.advisories)
    hit = next(a for a in r.advisories if a.cve == "CVE-2025-55182")
    assert hit.severity in ("critical", "high")
    assert "react-server-dom" in (hit.product or "") or "React" in hit.summary


@pytest.mark.skipif(not _net(), reason="無外部網路")
def test_cve_lookup_product_level():
    from redteam.cve_lookup import lookup
    # 產品級:不因版本過濾 — 列全部已發布 CVE
    r = lookup(product="django", ecosystem="pip")
    assert r.ok, r.error
    assert len(r.advisories) > 0
    assert "ghsa" in r.sources or "osv" in r.sources


@pytest.mark.skipif(not _net(), reason="無外部網路")
def test_cve_lookup_bad_id():
    from redteam.cve_lookup import lookup
    r = lookup(cve_id="DROP TABLE")
    assert not r.ok and "格式" in r.error
