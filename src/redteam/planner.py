"""Planner - DAG task graph + node state machine (spec §3.3 / §3.4).

DAG defines high-level phases (Recon -> Fingerprint -> Inject -> Verify -> PoC -> Report).
Each node runs an internal ReAct loop. Node status: not_started | in_flight | completed.
Supports checkpoint / resume.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class PlanNode:
    id: str
    phase: str
    target_type: str  # llm_app | web_service | hybrid
    action: str
    payload: Any = None
    status: str = "not_started"  # not_started | in_flight | completed | unknown
    result: Any = None
    side_effect_free: bool = True  # for resume in_flight policy


@dataclass
class Plan:
    target: str
    target_type: str
    nodes: list[PlanNode] = field(default_factory=list)

    def next_pending(self) -> PlanNode | None:
        for n in self.nodes:
            if n.status == "not_started":
                return n
        return None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "nodes": [
                {"id": n.id, "phase": n.phase, "target_type": n.target_type,
                 "action": n.action, "status": n.status, "result": n.result,
                 "side_effect_free": n.side_effect_free}
                for n in self.nodes
            ],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Plan":
        plan = cls(d["target"], d["target_type"])
        plan.nodes = [PlanNode(**{**n, "payload": None}) for n in d["nodes"]]
        return plan


class CheckpointStore:
    """Persist plan state for resume (spec §3.4)."""

    def __init__(self, dir_: str = "state"):
        self.dir = Path(dir_)
        self.dir.mkdir(exist_ok=True)

    def save(self, plan: Plan, tag: str | None = None) -> Path:
        ts = tag or time.strftime("%Y%m%d_%H%M%S")
        path = self.dir / f"checkpoint_{ts}.json"
        path.write_text(json.dumps(plan.to_dict(), indent=2))
        return path

    def load(self, path: str) -> Plan:
        return Plan.from_dict(json.loads(Path(path).read_text()))


def build_default_plan(target: str, target_type: str) -> Plan:
    """Construct a spec-compliant DAG skeleton for the target type."""
    plan = Plan(target, target_type)
    phases = ["recon", "fingerprint", "inject", "verify", "poc", "report"]
    for i, phase in enumerate(phases):
        plan.nodes.append(PlanNode(
            id=f"n{i+1}", phase=phase, target_type=target_type,
            action=f"run_{phase}",
            side_effect_free=(phase in ("recon", "fingerprint")),
        ))
    return plan
