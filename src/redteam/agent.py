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

from .cve_lookup import enrich as cve_enrich, lookup as cve_lookup_backend
from .guardtext import SYSTEM_RULE as GUARD_RULE, guard_observation
from .knowledge import (catalog as kb_catalog, get_by_id as kb_get,
                       load_library as kb_load, load_user_skills,
                       search as kb_search)
from .interactor import RedTeamHTTP
from .triage import triage as triage_score, sort_findings
from .version_watch import detect_releases, watch as version_watch
from .workspace import ProbeLog, Workspace


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

    def __init__(self, http: RedTeamHTTP, target: str, *, docker_bridge=None,
                 workspace: Workspace | None = None):
        self.http = http
        self.target = target
        self.docker_bridge = docker_bridge
        self.probe_count = 0
        self.max_probes = 60  # 硬性總探測量,防失控轟炸
        self.ws = workspace  # None = 不啟用工作區(向後兼容)
        self._kb = None  # get_playbook 知識庫 lazy load
        self._get_cache: dict[str, ToolResult] = {}  # 安全方法結果快取(省預算)
        self.probe_log: list[ProbeLog] = []  # 跨會話記憶的探測軌跡(含失敗)

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
            "description": ("Query public CVE sources (GHSA + OSV + NVD) with EPSS "
                            "likelihood + CISA KEV enrichment. Give either "
                            "cve_id (CVE-YYYY-NNNNN) for exact lookup, or product "
                            "(+ecosystem/version optional) for product-level listing of "
                            "ALL published CVEs — do not trust the target's claimed "
                            "version, verify which versions are affected and probe. "
                            "kev=true means actively exploited in the wild: verify first."),
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string"},
                    "product": {"type": "string"},
                    "ecosystem": {"type": "string",
                                  "description": "npm|pip|composer|maven|go|cargo|rubygems..."},
                    "version": {"type": "string"},
                    "likelihood": {"type": "boolean",
                                   "description": "set false to skip EPSS/KEV enrichment (faster)"},
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
            "description": ("Query the playbook library (attack theory / defense "
                            "checklist templates: OWASP GenAI LLM playbooks + web "
                            "methodology + user-injected markdown skills from "
                            "~/.tanli/skills). Call with no args to get a compact catalog; "
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
            "name": "read_tool_output",
            "description": ("Read back an offloaded large tool output by its file path "
                            "(only paths under this engagement's tool-outputs/ are "
                            "allowed). Use when a previous result shows [OFFLOADED ...]."),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "offset": {"type": "integer", "description": "char offset (default 0)"},
                    "limit": {"type": "integer", "description": "max chars (default 6000)"},
                },
                "required": ["path"],
            },
        },
        {
            "name": "write_note",
            "description": ("Persist a working note in the engagement workspace "
                            "(notes/<name>.md). Survives across sessions — future "
                            "runs on this target load findings/lessons automatically. "
                            "Good for: hypotheses to test later, dead-end reasons, "
                            "attack-surface maps."),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "filename-safe name"},
                    "content": {"type": "string"},
                },
                "required": ["name", "content"],
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
                    "reachability": {"type": "string", "enum": [
                        "direct", "low_priv", "auth_required",
                        "user_interaction", "internal_only"],
                        "description": "how reachable the flaw is for an attacker"},
                    "exfiltrated_data": {
                        "type": "array", "items": {"type": "string"},
                        "description": ("Verbatim snippets of sensitive data you LITERALLY "
                                        "captured from the target in earlier tool output "
                                        "(secret/config lines, PII, dumped rows). Each entry "
                                        "is redacted and listed in the report's formal "
                                        "'偷到的資料' section. Copy only text you actually "
                                        "observed — never paraphrase, never invent. Omit "
                                        "when nothing was actually extracted."),
                    },
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
            self.probe_log.append(ProbeLog(m, url, "blocked-scope", ok=False))
            return ToolResult(False, {"blocked": "scope"}, "BLOCKED by ScopeGuard — outside authorized scope")
        if rec.blocked_by_readonly:
            self.probe_log.append(ProbeLog(m, url, "blocked-readonly", ok=False))
            return ToolResult(False, {"blocked": "read_only"},
                              "BLOCKED by read-only fuse — non-safe method physically blocked")
        self.probe_log.append(ProbeLog(m, url, rec.status, ok=(rec.status or 0) < 400))
        text = (rec.body or b"").decode("utf-8", "replace")
        body_out = text[:3500]
        if self.ws is not None and len(text) > 3500:
            # 大輸出卸載(借鑑 RedAmon auto-offload):完整內容落盤,LLM 收 stub
            body_out = self.ws.offload(f"http{rec.status}", text)
        # 注入防護:目標內容包定界符 + 啟發式標記(借鑑 Decepticon)
        body_out, _hits = guard_observation(body_out, source=url)
        out = ToolResult(True, {
            "status": rec.status,
            "headers": {k: v for k, v in (rec.response_headers or {}).items()
                        if k.lower() in ("server", "x-powered-by", "content-type", "generator", "via")},
            "body": body_out,
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
            self.probe_log.append(ProbeLog("GET", self.target, "blocked", ok=False))
            return ToolResult(False, None, "target blocked by scope/read-only")
        self.probe_log.append(ProbeLog("GET", self.target, rec.status,
                                       ok=(rec.status or 0) < 400))
        html = (rec.body or b"").decode("utf-8", "replace")
        releases = detect_releases(html)
        hdrs = {k: v for k, v in (rec.response_headers or {}).items()
                if k.lower() in ("server", "x-powered-by", "generator", "via", "x-aspnet-version")}
        meta = re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                          html, re.I)
        head = html[:2500]
        if self.ws is not None and len(html) > 2500:
            head = self.ws.offload("fingerprint", html)
        head, _ = guard_observation(head, source=self.target)
        return ToolResult(True, {"status": rec.status, "headers": hdrs,
                                 "generator_meta": meta, "release_decls": releases,
                                 "body": head})

    def _t_cve_lookup(self, cve_id: str | None = None, product: str | None = None,
                      ecosystem: str | None = None, version: str | None = None,
                      likelihood: bool = True) -> ToolResult:
        r = cve_lookup_backend(cve_id=cve_id, product=product, ecosystem=ecosystem, version=version)
        if not r.ok:
            return ToolResult(False, {"error": r.error}, r.error)
        intel = {}
        if likelihood and r.advisories:
            # EPSS + CISA KEV 情報加權(失敗如實標 status,不編造分數)
            try:
                intel = cve_enrich(r.advisories)
            except Exception as e:  # noqa: BLE001
                intel = {"kev_status": f"error({e.__class__.__name__})"}
        advs = [{"cve": a.cve, "src": a.source, "sev": a.severity, "product": a.product,
                 "range": a.vulnerable_range, "patched": a.first_patched,
                 "pub": a.published, "epss": a.epss, "kev": a.kev,
                 "summary": a.summary[:160]} for a in r.advisories]
        # 高 likelihood 排前面(EPSS desc → KEV → severity),幫 agent 聚焦
        advs.sort(key=lambda a: (-(a.get("epss") or 0), not a.get("kev"),
                                 a["sev"] != "critical"))
        return ToolResult(True, {"sources": r.sources, "count": len(advs),
                                 "likelihood_intel": intel or "未啟用或不可用",
                                 "latest_advisory_date": r.latest_advisory_date,
                                 "advisories": advs[:40]},
                          "查無 CVE ≠ 無漏洞(注意資料源滯後;見 latest_advisory_date);"
                          "kev=true 的 CVE 已被真實利用,優先動態驗證")

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
            # 內建 playbook + 使用者注入的 markdown 技能(~/.tanli/skills)
            self._kb = kb_load() + load_user_skills()
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

    def _t_read_tool_output(self, path: str, offset: int = 0,
                            limit: int = 6000) -> ToolResult:
        if self.ws is None:
            return ToolResult(False, None, "工作區未啟用(--workspace 關閉)")
        try:
            return ToolResult(True, {"path": path,
                                     "content": self.ws.read_tool_output(path, offset, limit)})
        except ValueError as e:
            return ToolResult(False, None, str(e))

    def _t_write_note(self, name: str, content: str) -> ToolResult:
        if self.ws is None:
            return ToolResult(False, None, "工作區未啟用(--workspace 關閉)")
        p = self.ws.write_note(name, str(content)[:20000])
        return ToolResult(True, {"saved": str(p)})

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
6. If a probe returned LITERAL sensitive data (a secret/config line, PII, dumped
   records), pass those exact snippets in add_finding.exfiltrated_data so they land in
   the report's formal extracted-data section. Only copy text you actually saw in tool
   output — never guess or paraphrase; omit the field when nothing was extracted.
7. Stay inside the authorized scope; prefer read-only observation. You have a hard
   probe budget and a token budget.
8. When you have exhausted reasonable checks (or budget), call finish with a summary.
""" + GUARD_RULE + """
Keep working notes via write_note for anything worth carrying to a next session.
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
    triage_score: float = -1.0
    triage_factors: dict = field(default_factory=dict)
    kev: bool = False
    #: LLM 經 add_finding.exfiltrated_data 登錄的實際擷取片段(逐字觀測物),
    #: 報告生成時經 Finding.extracted → attach_exfil 進 §3(自動脫敏)
    exfiltrated: list[str] = field(default_factory=list)


@dataclass
class AgentRunResult:
    findings: list[AgentFinding] = field(default_factory=list)
    steps: int = 0
    tokens: int = 0
    probes: int = 0
    finished: bool = False
    summary: str = ""
    transcript: list[dict] = field(default_factory=list)
    workspace: str = ""
    engagement_package: str = ""


def run_agent(tools: AgentTools, brain, *, goal: str, max_steps: int = 30,
              token_budget: int = 200_000, console=None,
              engagement_brief: str = "") -> AgentRunResult:
    """自主 tool-loop:brain 決定每一步,工具層圍籬兜底。

    engagement_brief: RoE + OPPLAN + 跨會話記憶 的合成文本(借鑑
    Decepticon「行動前先注入紀律」;空字串 = 純預設行為)。
    """
    result = AgentRunResult()
    if tools.ws is not None:
        result.workspace = str(tools.ws.root)
    opening = (f"Authorized target: {tools.target}\nGoal: {goal}\n"
               f"Hard limits: max {max_steps} steps, {tools.max_probes} HTTP probes. ")
    if engagement_brief:
        opening += ("\nEngagement discipline (read before acting):\n" + engagement_brief
                    + "\nBegin with fingerprinting, then execute the OPPLAN phases.")
    else:
        opening += "Begin with fingerprinting, then plan your checks."
    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": opening},
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
            cve_arg = str(args.get("cve", ""))
            # triage(借鑑 CypherFix):固定公式風險分,確定性可稽核
            kev_hit = False
            epss_val: float | None = None
            try:
                if re.match(r"^CVE-\d{4}-\d{4,7}$", cve_arg, re.I):
                    from .cve_lookup import kev_set as _kev_set
                    kev_map, _st = _kev_set()
                    kev_hit = cve_arg.upper() in kev_map
            except Exception:  # noqa: BLE001 — KEV 不可用不阻斷記錄
                pass
            tr = triage_score(severity=str(args.get("severity", "info")),
                              confidence=float(args.get("confidence", 0.6)),
                              cve_epss=epss_val, kev=kev_hit,
                              reachability=str(args.get("reachability", "direct")))
            # exfiltrated_data:LLM 逐字登錄的真實擷取物 → AgentFinding.exfiltrated
            # → 報告 Finding.extracted → attach_exfil 進 §3(自動脫敏)。
            # 上限 10 筆、單筆 500 字,防 bulk dump 灌進報告。
            # 型別防禦(agy review):LLM 可能吐出 int/bool/dict 等非清單值,
            # 一律包成單元素清單,絕不迭代非可迭代物件(防擊垮 agent loop)。
            exfil_in = args.get("exfiltrated_data")
            if exfil_in is None:
                exfil_raw: list[Any] = []
            elif isinstance(exfil_in, (list, tuple)):
                exfil_raw = list(exfil_in)
            else:
                exfil_raw = [exfil_in]
            exfil = [str(x)[:500] for x in exfil_raw if str(x).strip()][:10]
            f = AgentFinding(
                title=str(args.get("title", ""))[:200],
                severity=str(args.get("severity", "info")).lower(),
                description=str(args.get("description", ""))[:2000],
                evidence=str(args.get("evidence", ""))[:2000],
                category=str(args.get("category", "agent")),
                cve=cve_arg,
                confidence=float(args.get("confidence", 0.6)),
                triage_score=tr.score, triage_factors=tr.factors, kev=kev_hit,
                exfiltrated=exfil,
            )
            result.findings.append(f)
            obs = ToolResult(True, {"recorded": f.title,
                                    "triage": tr.as_dict(),
                                    "exfil_logged": len(exfil)})
            if console:
                console.print(f"    [green]✎ finding: {f.title} ({f.severity}"
                              f" | triage {tr.score}"
                              f"{f' | exfil×{len(exfil)}' if exfil else ''})[/]")
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

    # ---- 收尾:EPSS 回填 triage(批次一次)+ 跨會話記憶累加 ----
    cve_findings = [f for f in result.findings
                    if re.match(r"^CVE-\d{4}-\d{4,7}$", f.cve or "", re.I)]
    if cve_findings:
        try:
            from .cve_lookup import epss_scores
            scores = epss_scores([f.cve for f in cve_findings])
            for f in cve_findings:
                e = scores.get(f.cve.upper())
                if e:
                    tr = triage_score(severity=f.severity, confidence=f.confidence,
                                      cve_epss=e["score"], kev=f.kev)
                    f.triage_score, f.triage_factors = tr.score, tr.factors
        except Exception:  # noqa: BLE001 — EPSS 缺援保留 severity 預設分
            pass
    if tools.ws is not None:
        fdicts = [{"title": f.title, "severity": f.severity, "cve": f.cve,
                   "triage_score": f.triage_score} for f in result.findings]
        pdicts = [p.to_dict() for p in tools.probe_log]
        lessons = [t.get("note", "") for t in result.transcript
                   if not t.get("ok") and t.get("note")]
        tools.ws.append_session(fdicts, pdicts,
                                [l for l in lessons if l][:10],
                                result.summary or "")
    return result
