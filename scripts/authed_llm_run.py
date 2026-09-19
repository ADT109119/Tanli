#!/usr/bin/env python3
"""探驪 LLM 軌道 runner:帶 Authorization header 打帶鑰 OpenAI 兼容閘道。

為什麼需要:探驪的 LLMTarget 目前不支援自訂 header(實務缺口,本次順帶補進
src/redteam/playbook.py 的 --llm-api-key-env 流程)。此腳本為本次授權測試的
過渡橋接:讀 NexusLLM key(從 hermes config)→ 建帶 Bearer 的 LLMTarget →
跑指定 playbook → 輸出與 tanli 相同的 probe 結果格式。

僅限授權測試使用。
"""
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from redteam.auth import ScopeGuard, verify_credential, credential_kid  # noqa: E402
from redteam.playbook import LLMTarget, PlaybookEngine, load_playbooks  # noqa: E402


def nexus_key() -> str:
    """NexusLLM key 在 config.yaml 的 api_key 行在 name 行「之前」→ 反向錨定取 field 3。"""
    text = (Path.home() / ".hermes/config.yaml").read_text(encoding="utf-8")
    key = ""
    for line in text.splitlines():
        m = re.match(r"\s*-?\s*api_key:\s*(\S+)", line)
        if m:
            key = m.group(1)
        if "name: NexusLLM" in line:
            return key
    raise SystemExit("NexusLLM key not found in config.yaml")


class AuthedLLMTarget(LLMTarget):
    """帶 Bearer token 的 LLMTarget(上游缺口過渡:覆寫 chat 加 header)。"""

    def __init__(self, *args, api_key: str | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_key = api_key

    def chat(self, messages, params=None, path="/v1/chat/completions"):
        # 上游 chat() 用固定 headers dict;此處用 RedTeamHTTP 直接帶 Authorization
        params = params or {}
        body = {
            "model": self.model or "gpt-4o",
            "messages": messages,
            "temperature": params.get("temperature", 0.0),
            "max_tokens": params.get("max_tokens", self.max_tokens),
        }
        if params.get("seed") is not None:
            body["seed"] = params["seed"]
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        rec = self.http.request("POST", self._endpoint(path), json=body, headers=headers)
        if rec.blocked_by_scope:
            return self._resp("", "blocked_by_scope", None)
        if rec.status is None or rec.status != 200:
            return self._resp("", f"http_{rec.status}", None)
        try:
            import json as _json
            payload = _json.loads((rec.body or b"").decode("utf-8", "replace"))
            msg = payload["choices"][0]["message"]
            # 推理型模型 content 可能為 null,退而取 reasoning
            text = msg.get("content") or msg.get("reasoning") or ""
            finish = payload["choices"][0].get("finish_reason", "")
            usage = payload.get("usage")
            return self._resp(text, finish, usage)
        except Exception as e:  # noqa: BLE001
            return self._resp("", f"parse_error: {e.__class__.__name__}", None)

    @staticmethod
    def _resp(text, finish, usage):
        from redteam.playbook import LLMResponse
        return LLMResponse(text=text, finish_reason=finish, usage=usage)


def main() -> None:
    target = sys.argv[1]
    cred = sys.argv[2]
    pub = sys.argv[3]
    model = sys.argv[4] if len(sys.argv) > 4 else "opencode/nemotron-3-ultra-free"
    pb_dir = os.environ.get("REDTEAM_PLAYBOOK_DIR", "playbooks/llm")
    single = os.environ.get("REDTEAM_SINGLE_PLAYBOOK") or None

    stmt, kid = verify_credential(Path(cred).read_text().strip(),
                                  Path(pub).read_text().strip())
    guard = ScopeGuard(stmt, Path(pub).read_text().strip(), credential_kid=kid)
    print(f"guard: authorized={guard.is_authorized()} kid={kid}")

    key = nexus_key()
    lt = AuthedLLMTarget(guard=guard, base_url=target, model=model,
                         timeout=45, max_tokens=256, rate_qps=1.0,
                         api_key=key)
    # 哨兵:先確認通路可用
    probe = lt.chat([{"role": "user", "content": "reply with exactly: PONG"}])
    print(f"smoke: finish={probe.finish_reason} text={probe.text[:60]!r}")
    if "PONG" not in (probe.text or "") and probe.finish_reason not in (None,):
        if not probe.text:
            print("!! smoke failed — aborting (通路或模型不可用)")
            raise SystemExit(2)

    pbs = load_playbooks(pb_dir, single=single)
    total_confirmed = 0
    for pb in pbs:
        if not pb.get("side_effect_free", True):
            print(f"  {pb.get('id')} {pb.get('name')}: side-effect → skipped by policy for this run")
            continue
        engine = PlaybookEngine(lt, max_probes=pb.get("max_probes", 30))
        try:
            prs = engine.run(pb)
        except Exception as e:  # noqa: BLE001
            print(f"  {pb.get('id')} FAILED: {e}")
            continue
        hits = [r for r in prs if r.passed]
        total_confirmed += len(hits)
        status = f"{len(hits)} confirmed" if hits else "guardrails held"
        print(f"  {pb.get('id')} {pb.get('name')}: {len(prs)} probes, {status}")
        for r in hits:
            ev = " | ".join(r.evidence)[:140] if r.evidence else (r.response_excerpt or "")[:140]
            print(f"    [HIT] {r.id} {r.name} (intent={r.intent}): {ev!r}")
    print(f"TOTAL CONFIRMED: {total_confirmed}")


if __name__ == "__main__":
    main()
