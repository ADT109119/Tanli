"""Autonomous agent loop — OpenCode/Hermes 級 tool-loop 自主性,安全圍籬內執行。

設計(spec §6 精神延伸,用戶 2026-09-19 需求):
- 靜態 6 節點 plan 之外,新增真正的 LLM tool-loop:模型自己決定下一步
  (探什麼、查哪個 CVE、動態怎麼試),直到達成目標或預算耗盡。
- 每個工具都是「圍籬內的原語」:ScopeGuard/read-only/token budget 在工具
  層強制,模型無法繞過(與 hermes 的 approval 分層同理:能力給足,權限收緊)。
- 不信任指紋版本原則寫進 system prompt:發現套件/框架 → cve_lookup 查全部
  CVE → 以被動指紋+動態安全探測交叉核實 → 才有資格宣稱漏洞。

Brain 可注入(FakeBrain 測試);生產用 OpenAI-compatible endpoint
(與 LLMJudge 同源配置 REDTEAM_JUDGE_*)。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from .cve_lookup import lookup as cve_lookup_backend
from .knowledge import catalog as kb_catalog, get_by_id as kb_get, load_library as kb_load, search as kb_search
from .interactor import RedTeamHTTP
from .version_watch import detect_releases, watch as version_watch


# ---------------------------------------------------------------------------
# Tool 層(每個工具 = 圍籬內原語)
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    ok: bool
    data: Any
    note: str = ""


class AgentTools:
    """綁定單一 target + ScopeGuard/read-only HTTP 客戶端的工具集。

    add_finding / finish 由 loop 內部處理;這裡只實作探測/查詢類工具。
    """

    def __init__(self, http: RedTeamHTTP, target: str, *, docker_bridge=None):
        self.http = http
        self.target = target
        self.docker_bridge = docker_bridge
        self.probe_count = 0
        self.max_probes = 60  # 硬性總探測量,防失控轟炸
        self._kb = None  # get_playbook 知識庫 lazy load
        self._get_cache: dict[str, ToolResult] = {}  # 安全方法結果快取(省預算)

    # ---- schema(提供給 brain) ----
    SCHEMAS: list[dict] = [
        {
            "name": "http_request",
            "description": ("Send an HTTP request to a URL inside the authorized scope. "
                            "Returns status, selected headers, and truncated body. "
                            "In read-only mode non-safe methods are physically blocked."),
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE"]},
                    "url": {"type": "string", "description": "Must stay within authorized scope"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "body": {"type": "string"},
                },
                "required": ["method", "url"],
            },
        },
        {
            "name": "fingerprint",
            "description": ("Passively fingerprint the target: fetch it, extract server "
                            "headers, generator meta, and any <pkg>@<ver> release "
                            "declarations (self-reported versions — treat as hypothesis, "
                            "never as truth)."),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "cve_lookup",
            "description": ("Query public CVE sources (GHSA + OSV + NVD). Give either "
                            "cve_id (CVE-YYYY-NNNNN) for exact lookup, or product "
                            "(+ecosystem/version optional) for product-level listing of "
                            "ALL published CVEs — do not trust the target's claimed "
                            "version, verify which versions are affected and probe."),
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string"},
                    "product": {"type": "string"},
                    "ecosystem": {"type": "string",
                                  "description": "npm|pip|composer|maven|go|cargo|rubygems..."},
                    "version": {"type": "string"},
                },
                "required": [],
            },
        },
        {
            "name": "version_watch",
            "description": ("Compare a specific pkg@version against GHSA for applicable "
                            "unpatched CVEs (fast, version-range matched). Only meaningful "
                            "for framework/ecosystem packages."),
            "parameters": {
                "type": "object",
                "properties": {"product": {"type": "string"}, "ecosystem": {"type": "string"},
                               "version": {"type": "string"}},
                "required": ["product", "version"],
            },
        },
        {
            "name": "web_config_probe",
            "description": ("Run the deterministic web-configuration probe suite against "
                            "the target (security headers, cookie flags, exposed paths, "
                            "method policies). Pure read-only, no Docker. Returns "
                            "confirmed config weaknesses with OWASP mapping."),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "nuclei_cve_probe",
            "description": ("Attempt a dynamic check of a specific CVE by running nuclei "
                            "with template tag = CVE id, inside the Docker sandbox. "
                            "Requires Docker; respects read-only & scope. This is the "
                            "'動態嘗試' path — match against the REAL detected product/version."),
            "parameters": {
                "type": "object",
                "properties": {"cve_id": {"type": "string"}},
                "required": ["cve_id"],
            },
        },
        {
            "name": "get_playbook",
            "description": ("Query the built-in playbook library (attack theory / defense "
                            "checklist templates: OWASP GenAI LLM playbooks + web "
                            "methodology). Call with no args to get a compact catalog; "
                            "then fetch full steps by id, or search by keyword/owasp. "
                            "Use playbooks as REFERENCE workflows for planning — they "
                            "encode standard attack/defense procedures."),
            "parameters": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "description": "Exact playbook id, e.g. llm-001"},
                    "query": {"type": "string", "description": "Keyword search across all playbooks"},
                    "owasp": {"type": "string", "description": "Filter by OWASP code, e.g. LLM01"},
                    "target_type": {"type": "string", "description": "Filter: llm_app | web_service"},
                },
                "required": [],
            },
        },
        {
            "name": "add_finding",
            "description": ("Record a confirmed-or-candidate finding. Cite concrete "
                            "evidence (request results / CVE IDs / probe output). "
                            "Never claim a finding you did not observe."),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "category": {"type": "string"},
                    "description": {"type": "string"},
                    "evidence": {"type": "string"},
                    "cve": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": ["title", "severity", "description", "evidence"],
            },
        },
        {
            "name": "finish",
            "description": "End the assessment with a short summary of what was done and found.",
            "parameters": {
                "type": "object",
                "properties": {"summary": {"type": "string"}},
                "required": ["summary"],
            },
        },
    ]

    # ---- dispatch ----
    def call(self, name: str, args: dict) -> ToolResult:
        if self.probe_count >= self.max_probes and name == "http_request":
            return ToolResult(False, None, f"probe budget exhausted ({self.max_probes})")
        fn = getattr(self, f"_t_{name}", None)
        if fn is None:
            return ToolResult(False, None, f"unknown tool: {name}")
        try:
            return fn(**args)
        except Exception as e:  # noqa: BLE001
            return ToolResult(False, None, f"tool error ({e.__class__.__name__}): {e}")

    def _t_http_request(self, method: str, url: str, headers: dict | None = None,
                        body: str | None = None) -> ToolResult:
        # 安全方法(GET/HEAD/OPTIONS)同請求快取:省探測預算與 token,結果一致
        m = method.upper()
        if m in ("GET", "HEAD", "OPTIONS") and body is None and not headers:
            hit = self._get_cache.get(f"{m} {url}")
            if hit is not None:
                return ToolResult(True, dict(hit.data) if isinstance(hit.data, dict) else hit.data,
                                  "cached(先前已探過同一請求,結果相同,未耗預算)")
        self.probe_count += 1
        rec = self.http.request(method.upper(), url, headers=headers,
                                data=body.encode() if body else None)
        if rec.blocked_by_scope:
            return ToolResult(False, {"blocked": "scope"}, "BLOCKED by ScopeGuard — outside authorized scope")
        if rec.blocked_by_readonly:
            return ToolResult(False, {"blocked": "read_only"},
                              "BLOCKED by read-only fuse — non-safe method physically blocked")
        text = (rec.body or b"").decode("utf-8", "replace")
        out = ToolResult(True, {
            "status": rec.status,
            "headers": {k: v for k, v in (rec.response_headers or {}).items()
                        if k.lower() in ("server", "x-powered-by", "content-type", "generator", "via")},
            "body_head": text[:3500],
            "body_len": len(text),
        })
        if m in ("GET", "HEAD", "OPTIONS") and body is None and not headers \
                and not rec.blocked_by_scope and not rec.blocked_by_readonly:
            self._get_cache[f"{m} {url}"] = out
        return out

    def _t_fingerprint(self) -> ToolResult:
        self.probe_count += 1
        rec = self.http.request("GET", self.target)
        if rec.blocked_by_scope or rec.blocked_by_readonly:
            return ToolResult(False, None, "target blocked by scope/read-only")
        html = (rec.body or b"").decode("utf-8", "replace")
        releases = detect_releases(html)
        hdrs = {k: v for k, v in (rec.response_headers or {}).items()
                if k.lower() in ("server", "x-powered-by", "generator", "via", "x-aspnet-version")}
        meta = re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                          html, re.I)
        return ToolResult(True, {"status": rec.status, "headers": hdrs,
                                 "generator_meta": meta, "release_decls": releases,
                                 "body_head": html[:2500]})

    def _t_cve_lookup(self, cve_id: str | None = None, product: str | None = None,
                      ecosystem: str | None = None, version: str | None = None) -> ToolResult:
        r = cve_lookup_backend(cve_id=cve_id, product=product, ecosystem=ecosystem, version=version)
        if not r.ok:
            return ToolResult(False, {"error": r.error}, r.error)
        advs = [{"cve": a.cve, "src": a.source, "sev": a.severity, "product": a.product,
                 "range": a.vulnerable_range, "patched": a.first_patched,
                 "pub": a.published, "summary": a.summary[:160]} for a in r.advisories]
        return ToolResult(True, {"sources": r.sources, "count": len(advs),
                                 "latest_advisory_date": r.latest_advisory_date,
                                 "advisories": advs[:40]},
                          "查無 CVE ≠ 無漏洞(注意資料源滯後;見 latest_advisory_date)")

    def _t_version_watch(self, product: str, version: str, ecosystem: str = "npm") -> ToolResult:
        wr = version_watch(product, ecosystem, version)
        if wr.error:
            return ToolResult(False, {"error": wr.error}, wr.error)
        return ToolResult(True, {"product": wr.product, "version": wr.current_version,
                                 "applicable_cves": [{"cve": m.cve, "sev": m.severity,
                                                     "patched": m.first_patched,
                                                     "range": m.vulnerable_range}
                                                    for m in wr.matches],
                                 "latest_advisory_date": wr.latest_advisory_date})

    def _t_web_config_probe(self) -> ToolResult:
        from .web_config import WebConfigProbe
        self.probe_count += 1
        probes = WebConfigProbe(http=self.http).run(self.target)
        hits = [{"name": p.name, "owasp": getattr(p, "owasp", ""),
                 "evidence": str(p.evidence)[:300]} for p in probes if p.passed]
        return ToolResult(True, {"checked": len(probes), "hit_count": len(hits),
                                 "hits": hits[:15]},
                          "deterministic 證據,可直接 add_finding")

    def _t_get_playbook(self, id: str | None = None, query: str | None = None,
                        owasp: str | None = None,
                        target_type: str | None = None) -> ToolResult:
        if self._kb is None:
            self._kb = kb_load()
        if id:
            doc = kb_get(self._kb, id)
            if doc is None:
                return ToolResult(False, {"catalog": kb_catalog(self._kb)},
                                  f"playbook id 不存在:{id}(見 catalog 選一個)")
            return ToolResult(True, {"playbook": doc.render(), "source": doc.source})
        hits = kb_search(self._kb, query=query, owasp=owasp, target_type=target_type)
        if not (query or owasp or target_type):
            return ToolResult(True, {"catalog": kb_catalog(self._kb),
                                     "count": len(self._kb)},
                              "目錄;用 id 取完整步驟,或 query/owasp 過濾")
        if not hits:
            return ToolResult(True, {"catalog": kb_catalog(self._kb)},
                              "無符合項;看目錄改用 id")
        return ToolResult(True, {"count": len(hits),
                                 "playbooks": [d.render() for d in hits[:4]]})

    def _t_nuclei_cve_probe(self, cve_id: str) -> ToolResult:
        if not re.match(r"^(cve-\d{4}-\d{4,7}|ghsa-[a-z0-9-]+)$", cve_id, re.I):
            return ToolResult(False, None, f"非法 tag: {cve_id!r}(僅 CVE/GHSA ID)")
        if self.docker_bridge is None:
            return ToolResult(False, None, "Docker 不可用 → nuclei 動態嘗試不可行(如實回報,勿臆測結果)")
        self.probe_count += 1
        import asyncio
        job = self.docker_bridge.nuclei_runner(self.target, tags=cve_id.upper())
        asyncio.run(self.docker_bridge.start(job))
        if job.status == "failed":
            return ToolResult(False, {"stderr": (job.stderr or "")[:400]}, "nuclei job failed")
        # ScannerBridge._parse_nuclei_jsonl 回傳 list[dict](每筆為一條 match)
        res = job.result
        matches = res if isinstance(res, list) else (res or {}).get("matches", [])
        brief = [{"name": m.get("info", {}).get("name", "?"),
                  "severity": m.get("info", {}).get("severity", "?"),
                  "matched": m.get("matched-at", "")} for m in matches[:10]]
        return ToolResult(True, {"tag": cve_id.upper(), "match_count": len(matches),
                                 "matches": brief,
                                 "note": "match_count=0 只代表該模板未命中,不等於無漏洞"
                                         "(模板覆蓋率有限)"})


# ---------------------------------------------------------------------------
# Brain(OpenAI-compatible + function calling)
# ---------------------------------------------------------------------------

class Brain(Protocol):
    def step(self, messages: list[dict]) -> dict:
        """回傳 {'thought': str, 'tool': str, 'args': dict} 或 {'thought', 'final': str}."""
        ...


SYSTEM_PROMPT = """You are Tanli, an autonomous red-team agent assessing ONE authorized target.
Method rules (mandatory):
1. NEVER trust self-reported versions (headers/generator/release meta are hypotheses).
   Identify the real product/framework, then call cve_lookup at PRODUCT level to get ALL
   published CVEs, and cross-check which versions are actually affected.
2. Verify dynamically: after matching a plausible CVE, use nuclei_cve_probe (or safe
   http_request probes) to attempt confirmation. A version-range match alone is a
   CANDIDATE, not a finding.
3. For web targets, run web_config_probe early — it is deterministic evidence.
4. Before planning attack checks, consult get_playbook (catalog first, then the
   relevant ids). The library encodes standard attack/defense procedures
   (OWASP GenAI LLM playbooks, web methodology) — adapt them to what you
   actually observed; never run a playbook blindly against the wrong product.
5. Record each real observation via add_finding with concrete evidence. Severity must
   match CVSS/impact. Never fabricate probe results; if a tool is unavailable or a
   probe is blocked, say so honestly.
6. Stay inside the authorized scope; prefer read-only observation. You have a hard
   probe budget and a token budget.
7. When you have exhausted reasonable checks (or budget), call finish with a summary.
Think step by step; one tool call per message."""


class OpenAIBrain:
    """OpenAI-compatible tool-calling brain(與 LLMJudge 同配置源)。"""

    def __init__(self, cfg: dict[str, Any]):
        from .config import Config
        env = Config.resolve_env()
        self.model = env.get("model") or cfg.get("model") or "gpt-4o"
        base_url = env.get("base_url") or cfg.get("base_url")
        api_key = env.get("api_key") or cfg.get("api_key")
        if not api_key and not base_url:
            raise RuntimeError(
                "agent 需要 LLM 端點:設 REDTEAM_JUDGE_BASE_URL / REDTEAM_JUDGE_API_KEY "
                "(或 OPENAI_API_KEY)")
        from openai import OpenAI
        kwargs: dict[str, Any] = {"api_key": api_key or "not-needed"}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = OpenAI(**kwargs)
        self.temperature = cfg.get("agent_temperature", 0.2)

    def step(self, messages: list[dict]) -> dict:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=messages,  # type: ignore[arg-type]
            tools=[{"type": "function", "function": s} for s in AgentTools.SCHEMAS],  # type: ignore[arg-type]
            tool_choice="auto",
            temperature=self.temperature,
            max_tokens=1200,
        )
        msg = resp.choices[0].message
        usage = getattr(resp, "usage", None)
        tokens = (usage.total_tokens if usage else 0)
        if getattr(msg, "tool_calls", None):
            tc = msg.tool_calls[0]  # type: ignore[index]
            try:
                args = json.loads(tc.function.arguments or "{}")  # type: ignore[union-attr]
            except json.JSONDecodeError:
                args = {}
            return {"thought": msg.content or "", "tool": tc.function.name,  # type: ignore[union-attr]
                    "args": args, "tokens": tokens, "_msg": msg}
        return {"thought": msg.content or "", "final": msg.content or "(no summary)",
                "tokens": tokens, "_msg": msg}


# ---------------------------------------------------------------------------
# Loop
# ---------------------------------------------------------------------------

@dataclass
class AgentFinding:
    title: str
    severity: str
    description: str
    evidence: str
    category: str = "agent"
    cve: str = ""
    confidence: float = 0.6


@dataclass
class AgentRunResult:
    findings: list[AgentFinding] = field(default_factory=list)
    steps: int = 0
    tokens: int = 0
    probes: int = 0
    finished: bool = False
    summary: str = ""
    transcript: list[dict] = field(default_factory=list)


def run_agent(tools: AgentTools, brain, *, goal: str, max_steps: int = 30,
              token_budget: int = 200_000, console=None) -> AgentRunResult:
    """自主 tool-loop:brain 決定每一步,工具層圍籬兜底。"""
    result = AgentRunResult()
    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": (
            f"Authorized target: {tools.target}\nGoal: {goal}\n"
            f"Hard limits: max {max_steps} steps, {tools.max_probes} HTTP probes. "
            f"Begin with fingerprinting, then plan your checks.")},
    ]
    for step_i in range(max_steps):
        try:
            out = brain.step(messages)
        except Exception as e:  # noqa: BLE001
            result.summary = f"brain 中途中斷({e.__class__.__name__}: {e})"
            break
        result.steps += 1
        result.tokens += out.get("tokens", 0)
        thought = out.get("thought", "")
        if console:
            console.print(f"  [magenta]◈ step {step_i+1}[/] {thought[:180]}")

        if "final" in out:
            result.finished = True
            result.summary = out["final"]
            break

        tool, args = out.get("tool", ""), out.get("args", {})
        if tool == "add_finding":
            f = AgentFinding(
                title=str(args.get("title", ""))[:200],
                severity=str(args.get("severity", "info")).lower(),
                description=str(args.get("description", ""))[:2000],
                evidence=str(args.get("evidence", ""))[:2000],
                category=str(args.get("category", "agent")),
                cve=str(args.get("cve", "")),
                confidence=float(args.get("confidence", 0.6)),
            )
            result.findings.append(f)
            obs = ToolResult(True, {"recorded": f.title})
            if console:
                console.print(f"    [green]✎ finding: {f.title} ({f.severity})[/]")
        elif tool == "finish":
            result.finished = True
            s = str(args.get("summary", "")).strip() or thought.strip()
            if not s:
                # 模型沒給總結:以實際狀態合成事實性摘要(不編造內容)
                s = (f"評估結束:{len(result.findings)} 項發現已記錄,"
                     f"{result.probes} 次探測 / {result.steps} 步。")
            result.summary = s
            break
        else:
            obs = tools.call(tool, args)

        result.transcript.append({"step": step_i + 1, "thought": thought[:500],
                                  "tool": tool, "args": args,
                                  "ok": obs.ok, "note": obs.note,
                                  "data_preview": str(obs.data)[:800]})
        messages.append({"role": "assistant", "content": thought or f"[call {tool}]"})
        messages.append({"role": "user", "content": (
            f"[tool {tool} -> {'OK' if obs.ok else 'FAIL'}] "
            f"{obs.note + ' | ' if obs.note else ''}"
            f"{json.dumps(obs.data, ensure_ascii=False, default=str)[:4000] if obs.data is not None else ''}"
            f"\n(remaining: {max_steps - step_i - 1} steps, "
            f"{tools.max_probes - tools.probe_count} probes, "
            f"~{max(token_budget - result.tokens, 0)} tokens)")})

        if result.tokens > token_budget:
            result.summary = result.summary or "token budget 耗盡,自主循環停止"
            break
    else:
        result.summary = result.summary or f"達成 max_steps={max_steps} 上限,未明確 finish"

    result.probes = tools.probe_count
    return result
