"""v0.0.3 修復驗證:上下文壓縮/token 預算=0/finish.achieved/owasp 登錄 +
報告端(狀態行/OWASP 正規化/category 修復建議/audit 落地)。"""

import pytest

from redteam.agent import (AgentTools, compress_messages, run_agent)
from redteam.auth import ScopeGuard
from redteam.interactor import RedTeamHTTP
from redteam.report import Finding, ReportGenerator

from tests.test_agent_loop import FakeBrain


@pytest.fixture
def tools():
    guard = ScopeGuard(None)
    http = RedTeamHTTP(guard=guard, read_only=True)
    return AgentTools(http, "http://127.0.0.1:9/", docker_bridge=None)


# ---------------- 上下文壓縮 ----------------

def test_compress_messages_trims_old_tool_outputs():
    msgs = [{"role": "system", "content": "sys"},
            {"role": "user", "content": "opening"}]
    for i in range(10):
        msgs.append({"role": "assistant", "content": f"think {i}"})
        msgs.append({"role": "user",
                     "content": f"[tool http_request -> OK] {'x' * 5000}"})
    out, saved = compress_messages(msgs, keep_recent=8, max_tool_chars=1200)
    assert saved > 0
    # 前兩則與最近 8 則不動
    assert out[0]["content"] == "sys" and out[1]["content"] == "opening"
    for m in out[-8:]:
        assert "[compressed" not in str(m.get("content", ""))
    # 舊的長 tool 結果被截+加指針
    old_tool_msgs = [m for m in out[2:-8] if str(m.get("content", "")).startswith("[tool ")]
    for m in old_tool_msgs:
        assert len(m["content"]) < 1500 and "[compressed" in m["content"]


def test_compress_idempotent():
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "o"}]
    for i in range(10):
        msgs.append({"role": "assistant", "content": "t"})
        msgs.append({"role": "user", "content": f"[tool fingerprint -> OK] {'y' * 5000}"})
    once, s1 = compress_messages(msgs)
    twice, s2 = compress_messages(once)
    assert s2 == 0  # 冪等:已壓縮不再重複壓
    assert [m["content"] for m in once] == [m["content"] for m in twice]


def test_compress_noop_when_short():
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "o"},
            {"role": "assistant", "content": "a"}, {"role": "user", "content": "[tool x -> OK] ok"}]
    out, saved = compress_messages(msgs)
    assert saved == 0 and out is msgs


def test_loop_compresses_under_compress_at(tools):
    """壓縮上線:估算超線即壓,不影響 findings 記錄。"""
    script = []
    for i in range(6):
        script.append({"thought": f"probe {i}", "tool": "fingerprint", "args": {}})
    script.append({"thought": "done", "tool": "finish", "args": {"summary": "ok"}})
    res = run_agent(tools, FakeBrain(script), goal="t", max_steps=10,
                    context_compress_at=1)  # 強迫每步都過壓縮路徑
    assert res.finished and res.summary == "ok"


def test_token_budget_zero_means_unlimited(tools):
    script = [{"thought": "p", "tool": "fingerprint", "args": {}} for _ in range(3)]
    script.append({"thought": "done", "tool": "finish", "args": {"summary": "fin"}})
    res = run_agent(tools, FakeBrain(script), goal="t", max_steps=10, token_budget=0)
    # tokens 累計但 budget=0 不觸發「預算耗盡」中斷
    assert res.finished and res.summary == "fin" and res.steps == 4


def test_finish_achieved_collected(tools):
    brain = FakeBrain([
        {"thought": "記一筆", "tool": "add_finding",
         "args": {"title": "t", "severity": "low", "description": "d",
                  "evidence": "e", "owasp": "A01"}},
        {"thought": "done", "tool": "finish",
         "args": {"summary": "s", "achieved": ["證明未登入可取資料", "取得版本指紋", ""]}},
    ])
    res = run_agent(tools, brain, goal="t", max_steps=5)
    assert res.achieved == ["證明未登入可取資料", "取得版本指紋"]
    assert res.findings[0].owasp == "A01"


def test_narration_no_tool_call_not_treated_as_final(tools):
    """run6 教訓回歸:thinking 模式模型會吐「純文字無 tool call」旁白。
    第一次必須提示表態並續跑;第二次連續純文字才算真最終總結。"""
    brain = FakeBrain([
        {"tool": "fingerprint", "args": {}},
        {"final": "分析:queryEvents 沒有 session 檢查,下一步要驗證..."},  # 旁白
        {"tool": "http_request", "args": {"method": "GET", "path": "/x"}},          # 被提示後續跑
        {"final": "評估完成,全部線索閉合。"},                                        # 連續第二次?不,中間有工具→重置
        {"final": "最終總結。"},
    ])
    res = run_agent(tools, brain, goal="t", max_steps=10)
    # 第一次旁白不終止(被提示);工具呼叫重置計數;第二次旁白(重置後)+第三次旁白...
    # 實際流:step1 tool, step2 narration(提示), step3 tool(重置), step4 narration(提示),
    # step5 narration 連續第二次 → 終止
    narr = [t for t in res.transcript if t["tool"] == "narration(no-tool-call)"]
    assert len(narr) == 2  # step2 與 step4 各記一筆
    assert res.finished and res.summary == "最終總結。"
    assert res.steps == 5


def test_single_narration_continues_loop(tools):
    """單次旁白後模型改用工具:迴圈正常續跑不被誤終止。"""
    brain = FakeBrain([
        {"final": "先看一下子來源..."},   # 純文字 → 提示
        {"tool": "fingerprint", "args": {}},
        {"tool": "finish", "args": {"summary": "ok", "achieved": ["x"]}},
    ])
    res = run_agent(tools, brain, goal="t", max_steps=5)
    assert res.finished and res.summary == "ok"
    assert any(t["tool"] == "narration(no-tool-call)" for t in res.transcript)


class RecordingBrain:
    """記錄每次 step() 收到的 messages(驗證迴圈注入的提醒文本)。"""

    def __init__(self, script):
        self.script = list(script)
        self.received: list[list[dict]] = []

    def step(self, messages):
        self.received.append([dict(m) for m in messages])
        item = self.script.pop(0) if self.script else {
            "thought": "收尾", "tool": "finish", "args": {"summary": "end"}}
        item = dict(item)
        item.setdefault("tokens", 100)
        item.setdefault("prompt_tokens", 500)
        return item


def test_major_finding_watchdog_reminds_once(tools):
    """run6b 教訓回歸:thought 自述「重大發現」但零 add_finding 時,
    下一步 tool 結果必須注入落檔提醒;且整個 run 只提醒一次。"""
    brain = RecordingBrain([
        {"thought": "**重大發現**:queryEvents 回傳了真實預約紀錄(含 patientId)",
         "tool": "http_request",
         "args": {"method": "POST",
                  "url": "http://127.0.0.1:9/api/queryEvents",
                  "body": "startdate=2020-01-01&enddate=2020-01-07"}},
        {"thought": "繼續探", "tool": "fingerprint", "args": {}},
        {"thought": "再探", "tool": "fingerprint", "args": {}},
        {"thought": "done", "tool": "finish", "args": {"summary": "ok"}},
    ])
    res = run_agent(tools, brain, goal="t", max_steps=6)
    # 只看最完整的一份快照(最後一步前的全量歷史),避免累積快照重疊重計
    full = max(brain.received, key=len)
    nag_count = sum(1 for m in full if m["role"] == "user"
                    and "尚未 add_finding" in m["content"])
    assert nag_count == 1  # 提醒恰一次( injected into one tool-result message only)
    assert res.finished


def test_major_finding_watchdog_silent_after_filing(tools):
    """已立案後再喊重大發現:不重覆提醒(result.findings 非空)。"""
    brain = RecordingBrain([
        {"thought": "記一筆", "tool": "add_finding",
         "args": {"title": "t", "severity": "low", "description": "d",
                  "evidence": "e"}},
        {"thought": "**重大發現**又一個", "tool": "fingerprint", "args": {}},
        {"thought": "done", "tool": "finish", "args": {"summary": "ok"}},
    ])
    res = run_agent(tools, brain, goal="t", max_steps=5)
    all_user_msgs = [m["content"] for snap in brain.received
                     for m in snap if m["role"] == "user"]
    assert not any("尚未 add_finding" in c for c in all_user_msgs)
    assert len(res.findings) == 1


def test_finish_refused_once_then_allowed(tools):
    """守門盲區回歸(run5 教訓):第一次 finish 被拒後,第二次 finish 必放行,
    且拒絶訊息要明示『再次 call finish 不再攔截』。"""
    from redteam.agent import AgentRunResult
    tools.scratchpad = ["TEST 驗證 endpoint X 是否回 701"]
    brain = FakeBrain([
        {"thought": "想收工", "tool": "finish", "args": {"summary": "early"}},
        {"thought": "補收", "tool": "finish",
         "args": {"summary": "real", "achieved": ["線索已閉合"]}},
    ])
    res = run_agent(tools, brain, goal="t", max_steps=5)
    assert res.finished and res.summary == "real"  # 第二次放行
    assert res.achieved == ["線索已閉合"]
    # transcript 有 deferred 記錄且拒絕訊息含再 finish 指引
    deferred = [t for t in res.transcript if t["tool"] == "finish(deferred)"]
    assert len(deferred) == 1
    # 第二次 finish 不再擋:總步數=2
    assert res.steps == 2


# ---------------- 報告端修復 ----------------

def _f(fid, sev, cat, owasp="", cve=""):
    return Finding(id=fid, attack_surface="web", category=cat + (f":{cve}" if cve else ""),
                   severity=sev,
                   title=f"t{fid}", description="d", steps=["s"], poc=None,
                   confidence=0.9, owasp=owasp)


def test_status_line_with_medium_only():
    r = ReportGenerator("http://x", "web")
    r.add_finding(_f("a1", "medium", "unauthenticated data access", owasp="A01"))
    r.add_finding(_f("a2", "low", "security-configuration", owasp="A05"))
    md = r.render()
    assert "無高危發現" not in md
    assert "狀態**: 完成 — 2 項發現" in md


def test_status_line_empty_and_high():
    r0 = ReportGenerator("http://x", "web")
    assert "無發現" in r0.render()
    r1 = ReportGenerator("http://x", "web")
    r1.add_finding(_f("h1", "high", "injection"))
    assert "草稿" in r1.render() and "人工複核" in r1.render()


def test_owasp_normalization_from_free_text():
    r = ReportGenerator("http://x", "web")
    r.add_finding(_f("a1", "medium", "x",
                     owasp="Broken Access Control / Unauthenticated Data Access "
                           "(OWASP A01:2021 — Broken Access Control; CWE-306)"))
    counts = r._owasp_counts()
    assert counts.get("A01") == 1 and "未映射" not in counts


def test_remediation_hits_agent_free_text_category():
    from redteam.report import _remediation_for
    class F:
        category = "Broken Access Control / Unauthenticated Data Access"
        owasp = ""
    assert "deny-by-default" in _remediation_for(F())

    class G:
        category = "broken_access_control / unauth_data_access"
        owasp = ""
    adv = _remediation_for(G())
    assert adv not in ("",) and "風險接受度" not in adv  # 不再退回通用話術


def test_write_passes_audit(tmp_path):
    r = ReportGenerator("http://x", "web")
    r.add_finding(_f("a1", "low", "info_disclosure"))
    p = r.write(out_dir=str(tmp_path), audit={"auth_hash": "abc123", "scope": "h/p",
                                              "tester": "jerry", "started": "T1",
                                              "ended": "T2"})
    md = p.read_text()
    assert "abc123" in md and "jerry" in md and "T1 → T2" in md
