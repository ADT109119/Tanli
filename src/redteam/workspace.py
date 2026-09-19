"""Agent Workspace — 借鑑 RedAmon:大輸出自動卸載 + 跨會話記憶(EvoGraph-lite)。

RedAmon 的兩個高性價比設計(取其精神,零依賴實作):
1. Auto-Offload:>20KB 的工具輸出自動寫檔,LLM 只收到 head/tail stub + 路徑
   — 一個 5MB 的 DOM dump 從此不會炸掉 context window。
2. EvoGraph-lite 跨會話記憶:findings、探測記錄(含失敗)、策略決策以 JSON
   持久化;新會話自動載入先前發現與失敗教訓,agent 不再每次從零開始。
   (RedAmon 用 Neo4j 圖;Tanli 定位純 CLI 套件 → 單檔 JSON,無服務依賴。)

目錄結構(每個 engagement 一個工作區):
  workspaces/<slug>/
    tool-outputs/   卸載的大輸出(<utc>-<tool>-<n>.txt)
    notes/          agent 筆記(write_note 工具)
    memory.json     跨會話記憶(findings/probes/lessons)
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: 超過此字節的 tool 輸出卸載到檔案(RedAmon 用 20KB,這裡取 8KB:
#: Tanli 的 token 預算普遍更小,更早卸載更省)。
OFFLOAD_THRESHOLD = 8000


def _slug(target: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", target).strip("-").lower()
    return s[:60] or "target"


@dataclass
class Workspace:
    """單一 engagement 的工作區(可重複使用 — 記憶跨會話累加)。"""
    root: Path
    target: str

    @classmethod
    def open(cls, target: str, base: str | Path = "workspaces") -> "Workspace":
        root = Path(base) / _slug(target)
        (root / "tool-outputs").mkdir(parents=True, exist_ok=True)
        (root / "notes").mkdir(parents=True, exist_ok=True)
        return cls(root=root, target=target)

    # ---- 大輸出卸載 -----------------------------------------------------
    def offload(self, tool: str, payload: str, keep_head: int = 2200,
                keep_tail: int = 800) -> str:
        """超過閾值 → 寫檔,回傳 head+tail stub + 路徑;否則原樣回傳。"""
        if len(payload.encode("utf-8", "replace")) <= OFFLOAD_THRESHOLD:
            return payload
        digest = hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:10]
        fname = f"{time.strftime('%Y%m%dT%H%M%S')}-{tool}-{digest}.txt"
        path = self.root / "tool-outputs" / fname
        if not path.exists():  # 同內容不重複寫
            path.write_text(payload, encoding="utf-8", errors="replace")
        stub = (payload[:keep_head]
                + f"\n... [OFFLOADED {len(payload)} chars → {path}"
                + f" | 完整內容可用 read_tool_output 工具查閱] ...\n"
                + payload[-keep_tail:])
        return stub

    def read_tool_output(self, path_str: str, offset: int = 0,
                         limit: int = 6000) -> str:
        """讀回卸載內容(只允許本工作區 tool-outputs/ 內 — 路徑圍籬)。"""
        p = Path(path_str).resolve()
        allowed = (self.root / "tool-outputs").resolve()
        if not str(p).startswith(str(allowed) + "/") or not p.is_file():
            raise ValueError(f"僅允許讀取 {allowed}/ 下的卸載檔")
        text = p.read_text(encoding="utf-8", errors="replace")
        return text[offset:offset + limit]

    # ---- agent 筆記 -----------------------------------------------------
    def write_note(self, name: str, content: str) -> str:
        name = re.sub(r"[^a-zA-Z0-9._-]", "_", name)[:60] or "note"
        if not name.endswith(".md"):
            name += ".md"
        p = self.root / "notes" / name
        p.write_text(content, encoding="utf-8")
        return str(p)

    # ---- 跨會話記憶(EvoGraph-lite)-------------------------------------
    def _mem_path(self) -> Path:
        return self.root / "memory.json"

    def load_memory(self) -> dict[str, Any]:
        if self._mem_path().exists():
            try:
                mem = json.loads(self._mem_path().read_text(encoding="utf-8"))
                if isinstance(mem, dict):
                    return mem
            except (json.JSONDecodeError, OSError):
                pass  # 壞檔 → 如實從空開始,不炸
        return {"target": self.target, "sessions": 0, "findings": [],
                "probes": [], "lessons": []}

    def save_memory(self, mem: dict[str, Any]) -> None:
        self._mem_path().write_text(
            json.dumps(mem, ensure_ascii=False, indent=1), encoding="utf-8")

    def append_session(self, findings: list[dict], probes: list[dict],
                       lessons: list[str], summary: str) -> dict[str, Any]:
        """會話結束時累加記憶。probes 記 (method,url,status,ok) — 失敗探測
        是下一會話最有價值的情報(別再浪費預算)。"""
        mem = self.load_memory()
        mem["sessions"] = int(mem.get("sessions", 0)) + 1
        mem["last_run"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        mem["last_summary"] = summary[:1500]
        seen_f = {(f.get("title"), f.get("cve")) for f in mem["findings"]}
        for f in findings:
            if (f.get("title"), f.get("cve")) not in seen_f:
                mem["findings"].append(f)
        seen_p = {(p.get("method"), p.get("url"), p.get("status"))
                  for p in mem["probes"]}
        for p in probes:
            if (p.get("method"), p.get("url"), p.get("status")) not in seen_p:
                mem["probes"].append(p)
        mem["probes"] = mem["probes"][-400:]  # 無界成長防護
        mem["lessons"] = list(dict.fromkeys(mem.get("lessons", []) + lessons))[-50:]
        self.save_memory(mem)
        return mem

    def memory_prompt_block(self, max_items: int = 12) -> str:
        """新會話開始時注入 prompt:先前發現 + 已探過/失敗過的路徑。"""
        mem = self.load_memory()
        if not mem.get("sessions"):
            return ""
        lines = [f"=== CROSS-SESSION MEMORY (prior sessions: {mem['sessions']},"
                 f" last: {mem.get('last_run', '?')}) ==="]
        fs = mem.get("findings", [])[-max_items:]
        if fs:
            lines.append("Prior findings (do NOT re-derive; verify only if new evidence):")
            for f in fs:
                lines.append(f"  - [{f.get('severity', '?')}] {f.get('title', '')[:90]}"
                             + (f" ({f.get('cve')})" if f.get("cve") else ""))
        ps = mem.get("probes", [])
        failed = [p for p in ps if not p.get("ok")][-max_items:]
        seen404 = [p for p in ps if p.get("status") in (404, 403, 405)][-max_items:]
        if failed:
            lines.append("Failed probes in the past — do not retry blindly:")
            for p in failed:
                lines.append(f"  - {p.get('method')} {str(p.get('url', ''))[:90]}"
                             f" -> {p.get('status', 'blocked')}")
        if seen404:
            lines.append("Confirmed-dead paths (404/403/405) — skip:")
            for p in seen404:
                lines.append(f"  - {p.get('method')} {str(p.get('url', ''))[:90]}")
        for lesson in mem.get("lessons", [])[-6:]:
            lines.append(f"  * lesson: {lesson[:160]}")
        return "\n".join(lines)


@dataclass
class ProbeLog:
    """給 append_session 的精簡探測記錄(不落敏感標頭/cookie)。"""
    method: str
    url: str
    status: int | str | None
    ok: bool = True

    def to_dict(self) -> dict:
        return {"method": self.method, "url": self.url[:200],
                "status": self.status, "ok": self.ok}
