"""knowledge(Playbook 知識庫)與 agent get_playbook 工具測試。"""

import pytest

from redteam.agent import AgentTools, run_agent
from redteam.auth import ScopeGuard
from redteam.interactor import RedTeamHTTP
from redteam.knowledge import catalog, get_by_id, load_library, search


class FakeBrain:
    def __init__(self, script):
        self.script = list(script)

    def step(self, messages):
        item = self.script.pop(0) if self.script else {"final": "done"}
        item = dict(item)  # type: ignore[var-annotated]
        if "tokens" not in item:
            item["tokens"] = 50  # type: ignore[assignment]
        return item


@pytest.fixture(scope="module")
def lib():
    docs = load_library()
    assert docs, "playbooks/ 知識庫不應為空"
    return docs


def test_library_loads_all_playbooks(lib):
    ids = {d.id for d in lib}
    # 5 條 LLM + 1 條 web 方法論全部入庫(含此前無引用的 playbook_6 孤檔)
    for want in ("llm-001", "llm-002", "llm-003", "llm-004", "llm-005", "web-006"):
        assert want in ids
    by_id = {d.id: d for d in lib}
    assert by_id["llm-001"].executable is True
    assert by_id["web-006"].executable is False  # 方法論不直接執行


def test_llm_playbooks_pass_safety_gate(lib):
    for d in lib:
        if d.executable:
            assert d.payload_policy in ("benign", "simulated")


def test_web006_methodology_has_steps(lib):
    doc = get_by_id(lib, "web-006")
    assert doc is not None
    kinds = [s["name"] for s in doc.steps]
    # playbook_6 的標準流程應完整可查
    for step in ("recon", "fingerprint", "probe", "automate", "verify", "poc"):
        assert step in kinds
    text = doc.render()
    assert "OR 1=1" in text  # 探測手法細節保留


def test_search_by_owasp_and_keyword(lib):
    hits = search(lib, owasp="LLM01")
    assert [d.id for d in hits] == ["llm-001"]
    hits = search(lib, query="jailbreak")
    assert any(d.id == "llm-001" for d in hits)
    hits = search(lib, query="sql")
    assert any(d.id == "web-006" for d in hits)
    # target_type 過濾
    hits = search(lib, target_type="web_service")
    assert all(d.target_type == "web_service" for d in hits)
    assert search(lib, query="不存在的東西xyz") == []


def test_get_by_id_miss_returns_none(lib):
    assert get_by_id(lib, "llm-999") is None


def test_catalog_shape(lib):
    c = catalog(lib)
    assert all({"id", "name", "owasp", "target_type", "executable"} <= set(row) for row in c)


# ---- agent 工具整合 ----

@pytest.fixture
def tools():
    http = RedTeamHTTP(guard=ScopeGuard(None), read_only=True)
    return AgentTools(http, "http://127.0.0.1:9/", docker_bridge=None)


def test_agent_get_playbook_catalog_then_detail(tools):
    brain = FakeBrain([
        {"thought": "先看目錄", "tool": "get_playbook", "args": {}},
        {"thought": "取 llm-001", "tool": "get_playbook", "args": {"id": "llm-001"}},
        {"thought": "取 web 方法論", "tool": "get_playbook", "args": {"id": "web-006"}},
        {"final": "done"},
    ])
    res = run_agent(tools, brain, goal="t", max_steps=6)
    t0, t1, t2 = res.transcript[0], res.transcript[1], res.transcript[2]
    assert t0["ok"] and "catalog" in t0["data_preview"]
    assert t1["ok"] and "llm-001" in t1["data_preview"]
    assert t2["ok"] and "web-006" in t2["data_preview"]


def test_agent_get_playbook_search(tools):
    brain = FakeBrain([
        {"thought": "查 SQL 相關", "tool": "get_playbook",
         "args": {"query": "sql"}},
        {"final": "done"},
    ])
    res = run_agent(tools, brain, goal="t", max_steps=4)
    t = res.transcript[0]
    assert t["ok"] and "web-006" in t["data_preview"]


def test_agent_get_playbook_bad_id_guides_to_catalog(tools):
    brain = FakeBrain([
        {"thought": "亂猜 id", "tool": "get_playbook", "args": {"id": "nope-1"}},
        {"final": "done"},
    ])
    res = run_agent(tools, brain, goal="t", max_steps=4)
    t = res.transcript[0]
    assert t["ok"] is False
    assert "catalog" in t["data_preview"]  # 失敗時給目錄引導自糾


def test_agent_tool_count_includes_playbook(tools):
    names = [s["name"] for s in AgentTools.SCHEMAS]
    assert "get_playbook" in names
    # dispatch 走 _t_get_playbook 且 schema/實作參數名一致
    tr = tools.call("get_playbook", {"owasp": "LLM08"})
    assert tr.ok and "llm-002" in str(tr.data)
