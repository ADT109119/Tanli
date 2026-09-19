"""Playbook 知識庫(攻擊理論作為可查詢知識)— agent `get_playbook` 工具後端。

設計(用戶 2026-09-19 確認):防禦準則與攻擊理論有範本與標準流程價值,
自主 agent 規劃時應能查詢既有劇本作為參考,而不是每靠自己臨場發揮。

不做向量資料庫:YAML 劇本本身即知識庫,結構化索引 + 關鍵字過濾即可
(零依賴、可稽核、所見即檔內原文)。

兩類知識源:
1. 執行型劇本 playbooks/llm/*.yaml — 經 PlaybookLoader 安全閘門驗證
   (payload_policy 必須 benign/simulated),供 llm_playbook 掃描器執行,
   此處同時作為 agent 的攻擊流程參考。
2. 方法型劇本 playbooks/web/*.yaml — 方法論格式(recon→…→poc 標準流程),
   供 agent 規劃參考;不直接執行(web 執行路徑走掃描器,受 read-only/
   ScopeGuard 圍籬)。

本模組只讀不改:任何執行仍需經過原管線的授權與圍籬檢查。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .playbook import PlaybookLoader


def _pkg_playbooks(*sub: str) -> Path:
    """package-relative playbooks 路徑(支援從任意 cwd 執行)。"""
    here = Path(__file__).resolve().parent  # src/redteam
    return here.parent.parent.joinpath("playbooks", *sub)


def _dirs(default_dirs: tuple[str, ...]) -> list[Path]:
    out = []
    for d in default_dirs:
        p = Path(d)
        if not p.exists():
            p = _pkg_playbooks(*Path(d).parts[1:])  # "playbooks/llm" → pkg
        if p.exists():
            out.append(p)
    return out


@dataclass
class PlaybookDoc:
    """一條可查詢的知識(執行型或方法型)。"""
    id: str
    name: str
    owasp: str = ""
    target_type: str = ""
    phase: str = ""
    payload_policy: str = "benign"
    summary: str = ""
    steps: list[dict] = field(default_factory=list)  # [{kind, name, detail}]
    source: str = ""
    executable: bool = False  # True = llm_playbook 掃描器可直接執行

    def render(self) -> str:
        """給 agent 的完整知識文本(結構化、緊湊)。"""
        lines = [
            f"[{self.id}] {self.name}",
            f"owasp={self.owasp or '—'} target={self.target_type or '—'} "
            f"phase={self.phase or '—'} payload_policy={self.payload_policy} "
            f"executable_by_scanner={self.executable}",
        ]
        if self.summary:
            lines.append(f"summary: {self.summary[:400]}")
        for s in self.steps:
            lines.append(f"  - ({s.get('kind','')}) {s.get('name','')}: "
                         f"{str(s.get('detail',''))[:260]}")
        return "\n".join(lines)


def _from_llm(pb: dict, src: str) -> PlaybookDoc:
    probes = pb.get("probes", [])
    steps = [{
        "kind": "probe",
        "name": p.get("name", p.get("id", "?")),
        "detail": (str(p.get("template") or p.get("messages") or "")[:260]),
    } for p in probes[:12]]
    baseline = any("baseline" in str(p.get("id", "")).lower() for p in probes)
    detect = sorted({r.get("kind", "")
                     for p in probes for r in (p.get("detect", {}) or {}).get("rules", [])
                     if isinstance(r, dict)})
    summary = (f"{len(probes)} probes; baseline_control={baseline}; "
               f"detect_rules={','.join(d for d in detect if d)}; "
               f"session_reset={pb.get('session', {}).get('reset', False)}")
    return PlaybookDoc(
        id=str(pb.get("id", src)), name=str(pb.get("name", "")),
        owasp=str(pb.get("owasp", "")), target_type=str(pb.get("target_type", "")),
        phase=str(pb.get("phase", "")),
        payload_policy=str(pb.get("payload_policy", "benign")),
        summary=summary, steps=steps, source=src, executable=True)


def _from_method(pb: dict, src: str) -> PlaybookDoc:
    raw_steps = pb.get("steps")
    steps: list[dict] = []
    if isinstance(raw_steps, dict):  # {recon: "...", verify: "..."}
        steps = [{"kind": "method", "name": str(k), "detail": str(v)}
                 for k, v in raw_steps.items()]
    elif isinstance(raw_steps, list):  # [{recon: "..."}, {probe: [...]}]
        for item in raw_steps:
            if isinstance(item, dict):
                for k, v in item.items():
                    steps.append({"kind": "method", "name": str(k),
                                  "detail": ", ".join(map(str, v)) if isinstance(v, list) else str(v)})
    return PlaybookDoc(
        id=str(pb.get("id", src)), name=str(pb.get("name", "")),
        owasp=str(pb.get("owasp", "")), target_type=str(pb.get("target_type", "")),
        phase=str(pb.get("phase", "")),
        payload_policy=str(pb.get("payload_policy", "methodology-only")),
        summary=f"方法論劇本(不直接執行;執行走掃描器管線)。"
                f"side_effect_free={pb.get('side_effect_free', '未宣告')}",
        steps=steps, source=src, executable=False)


def load_library(dirs: tuple[str, ...] = ("playbooks/llm", "playbooks/web")) -> list[PlaybookDoc]:
    """載入全部知識源;單檔損壞跳過但保留其餘(知識庫可用性優先)。"""
    docs: list[PlaybookDoc] = []
    for d in _dirs(dirs):
        is_llm = d.name == "llm"
        for f in sorted(d.glob("*.yaml")):
            try:
                raw = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
                if is_llm:
                    PlaybookLoader.validate(raw)  # 安全閘門同執行路徑
                    docs.append(_from_llm(raw, str(f)))
                elif raw.get("steps"):  # 方法論格式:steps 為 dict 或 list 皆可
                    docs.append(_from_method(raw, str(f)))
            except Exception:  # noqa: BLE001 — 損壞劇本不入庫
                continue
    return docs


def search(lib: list[PlaybookDoc], *, query: str | None = None,
           owasp: str | None = None, target_type: str | None = None) -> list[PlaybookDoc]:
    """關鍵字/類別過濾(id、name、owasp、summary、steps 皆納入比對)。"""
    out = lib
    if target_type:
        t = target_type.lower()
        out = [d for d in out if t in d.target_type.lower()]
    if owasp:
        o = owasp.lower()
        out = [d for d in out if o in d.owasp.lower()]
    if query:
        q = query.lower()
        def hit(d: PlaybookDoc) -> bool:
            blob = " ".join([d.id, d.name, d.owasp, d.summary] +
                            [f"{s.get('kind','')} {s.get('name','')} {s.get('detail','')}"
                             for s in d.steps]).lower()
            # 多詞查詢:全部詞都要命中
            return all(w in blob for w in re.findall(r"\w+", q))
        out = [d for d in out if hit(d)]
    return out


def get_by_id(lib: list[PlaybookDoc], doc_id: str) -> PlaybookDoc | None:
    want = doc_id.strip().lower()
    for d in lib:
        if d.id.lower() == want:
            return d
    return None


def catalog(lib: list[PlaybookDoc]) -> list[dict]:
    """精簡目錄(給 agent 先看清單再取全文,省 token)。"""
    return [{"id": d.id, "name": d.name, "owasp": d.owasp,
             "target_type": d.target_type, "executable": d.executable}
            for d in lib]
