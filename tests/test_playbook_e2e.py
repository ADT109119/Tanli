"""LLM playbook → 真實靶場 端到端測試(M6)。

PlaybookEngine 打真實 TargetLab(HTTP,非 mock),驗證:
- vulnerable 靶場 → playbook_1(越獄)確認出 LLM01 finding(含 CVSS)
- hardened 靶場 → 0 finding(典範目標不誤報)
全程 127.0.0.1、無 Docker、無 API key。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from redteam.findings import convert_all
from redteam.interactor import ScopeGuard
from redteam.playbook import LLMTarget, PlaybookEngine, load_playbooks
from redteam.target_lab import TargetLab

REPO = Path(__file__).parent.parent
PB1 = str(REPO / "src" / "redteam" / "playbooks" / "llm" / "playbook_1.yaml")


def _run_playbook(behavior: str) -> tuple[list, list]:
    pbs = load_playbooks(single=PB1)
    assert len(pbs) == 1
    pb = pbs[0]
    results: list = []
    with TargetLab(behavior=behavior) as lab:
        target = LLMTarget(
            ScopeGuard(None), lab.base_url, model="redteam-lab", rate_qps=100
        )
        engine = PlaybookEngine(target, max_probes=pb.get("max_probes", 30))
        results = engine.run(pb)
    return results, convert_all({"llm_playbook": results})


def test_vulnerable_lab_produces_finding():
    results, findings = _run_playbook("vulnerable")
    # 引擎確實打過靶場(有 probe 結果)
    assert len(results) >= 2
    # 越獄成功 → 至少 1 個 finding,且欄位完整
    assert len(findings) >= 1
    for f in findings:
        assert f.attack_surface == "llm"
        assert f.source == "llm_playbook"
        assert f.owasp.startswith("LLM")
        assert f.cvss_score > 0
        assert f.cvss_vector.startswith("CVSS:3.1/")
        assert f.confidence > 0
    # evidence 帶哨兵標記(攻擊成功錨點)
    joined = " ".join([f.evidence for f in findings]
                      + [s for f in findings for s in f.steps]
                      + [f.poc or "" for f in findings])
    assert "REDTEAM_MARKER_4821" in joined


def test_hardened_lab_no_finding():
    results, findings = _run_playbook("hardened")
    # 打過靶場但典範目標不得誤報
    assert len(results) >= 2
    assert findings == []


def test_baseline_probe_never_becomes_finding():
    """基準線探測(intent/name=baseline)是護欄存在證明,絕不可成 finding。

    這是 M6 修正的真 bug:修前 hardened 靶場會因 p1 baseline refused
    被 from_llm_probes 誤判成漏洞。
    """
    from redteam.findings import from_llm_probes
    from redteam.playbook import ProbeResult

    prs = [
        ProbeResult(id="p1", name="baseline-x", owasp="LLM01", category="llm01",
                    severity="medium", passed=True, intent="baseline_refused"),
        ProbeResult(id="p1b", name="baseline-y", owasp="LLM01", category="llm01",
                    severity="medium", passed=True),  # 無 intent,靠 name 慣例
        ProbeResult(id="p2", name="real-attack", owasp="LLM01", category="llm01",
                    severity="high", passed=True),
    ]
    fs = from_llm_probes(prs, [0])
    assert len(fs) == 1
    assert "real-attack" in fs[0].title
