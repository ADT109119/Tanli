"""CLI - spec §10. typer-based entrypoint.

Commands:
  redteam run TARGET [--target-type] [--dry-run] [--auth-cred] [--resume]
  redteam gen-cred --scope --key --out
  redteam self-test
  redteam --help
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console

from . import __version__
from .auth import ScopeGuard, ScopeStatement, ScopeEntry, sign_credential, verify_credential
from .config import Config
from .interactor import RedTeamHTTP
from .judge import LLMJudge
from .planner import CheckpointStore, build_default_plan
from .report import Finding, ReportGenerator
from .sandbox import DockerSandbox
from .scanners import ScannerBridge

app = typer.Typer(name="redteam", help="Autonomous Red Team Agent - LLM + Web security testing")
console = Console()


def _detect_target_type(url: str) -> str:
    """Spec §3.3 profiling: heuristic target_type auto-detection."""
    if any(m in url for m in ("/v1/chat", "/api/generate", "/chat/completions")):
        return "llm_app"
    return "web_service"  # default for ambiguous/general web


def _load_guard(auth_cred: str | None, public_key: str | None) -> ScopeGuard:
    """Build a ScopeGuard from a signed JWS credential + issuer public key.

    - No credential  -> ScopeGuard(None): localhost-only fallback (spec §5.1).
    - Credential + public key -> verify JWS, load ScopeStatement, enforce it.
    - Credential without public key -> error (never silently treat as authorized).
    """
    if not auth_cred:
        return ScopeGuard(None)
    if not public_key:
        raise RuntimeError(
            "--auth-cred requires --public-key (issuer Ed25519 public key) "
            "or REDTEAM_PUBLIC_KEY; refusing to trust unverifiable credential."
        )
    token = Path(auth_cred).read_text().strip()
    key_path = Path(public_key)
    if not key_path.exists():
        raise RuntimeError(f"public key file not found: {public_key}")
    pub_pem = key_path.read_text().strip()
    stmt, kid = verify_credential(token, pub_pem)
    guard = ScopeGuard(stmt, pub_pem, credential_kid=kid)
    # CRL: refuse to operate as authorized when the credential has been revoked.
    if guard.is_revoked():
        raise RuntimeError(
            f"credential kid={kid!r} is in the revocation list "
            "(REDTEAM_REVOKED_KIDS); refusing to run with a revoked credential."
        )
    return guard


@app.command()
def run(
    target: str = typer.Argument(..., help="Target URL"),
    target_type: Optional[str] = typer.Option(None, "--target-type", "-t", help="llm_app|web_service|hybrid (overrides auto-detect)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Output plan only, no attacks"),
    auth_cred: Optional[str] = typer.Option(None, "--auth-cred", help="Signed JWS credential file"),
    public_key: Optional[str] = typer.Option(None, "--public-key", help="Issuer Ed25519 public key (PEM) for credential verification"),
    resume: Optional[str] = typer.Option(None, "--resume", help="Checkpoint file to resume from"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="config.yaml path"),
    full: bool = typer.Option(False, "--full", help="Disable redaction (requires auth credential)"),
    scanners: str = typer.Option("auto", "--scanners", "-S", help="auto|none|web_config|nuclei|sqlmap|zap|all|llm_playbook (auto uses all for web, llm_playbook for llm)"),
    playbook: Optional[str] = typer.Option(None, "--playbook", help="specific LLM playbook YAML (llm_playbook mode)"),
    zap_mode: str = typer.Option("baseline", "--zap-mode", help="ZAP scan mode: baseline|full|api (default baseline; full=active SQLi/XSS/SSRF scanning)"),
    zap_api_format: Optional[str] = typer.Option(None, "--zap-api-format", help="ZAP api mode format: openapi|soap|graphql (required when --zap-mode api)"),
    nuclei_severity: Optional[str] = typer.Option(None, "--nuclei-severity", help="nuclei -severity (default: low,medium,high,critical; pass '' to disable filter)"),
    nuclei_exclude_protocols: Optional[str] = typer.Option(None, "--nuclei-exclude-protocols", help="nuclei -exclude-protocols (default: dns,code,file,websocket,whois; pass '' to disable)"),
    read_only: bool = typer.Option(False, "--read-only", help="生產環境保險絲:HTTP 層物理封鎖非安全方法(僅 GET/HEAD/OPTIONS 離網),sqlmap/ZAP full/api 直接拒絕,nuclei 限速"),
    auth_header: Optional[str] = typer.Option(None, "--auth-header", help="每次請求附加標頭,例 'Authorization: Bearer *** -- 值絕不進報告/日誌"),
    cve_watch: bool = typer.Option(False, "--cve-watch", help="指紋若含 <pkg>@<ver> 宣告,查 GitHub Advisory DB 列適用未修 CVE+修復版"),
):
    """Run red-team assessment against a target."""
    cfg = Config.load(config_path)
    ttype = target_type or _detect_target_type(target)
    if auth_header and read_only:
        console.print("[yellow]--read-only 生效中:--auth-header 僅供 GET 探測帶權限的只讀端點(如 /v1/models)[/]")

    # Authorization (real verbose check)
    try:
        guard = _load_guard(auth_cred, public_key)
    except RuntimeError as e:
        console.print(f"[red]Authorization: {e}[/]")
        raise typer.Exit(1)
    if guard.is_authorized():
        console.print("[green]Signed credential loaded and verified[/]")
    else:
        console.print("[yellow]No credential → localhost-only scope enforced[/]")
        if full:
            console.print("[red]--full (disable redaction) requires a signed credential.[/]")
            raise typer.Exit(1)

    # Plan (resume or fresh)
    store = CheckpointStore()
    if resume:
        plan = store.load(resume)
        if plan.target != target:
            console.print(
                f"[red]--resume checkpoint targets {plan.target!r}, but this run "
                f"targets {target!r} — refusing to mix runs.[/]"
            )
            raise typer.Exit(1)
        console.print(f"[cyan]Resumed from {resume}, {sum(1 for n in plan.nodes if n.status=='completed')} nodes done[/]")
    else:
        plan = build_default_plan(target, ttype)

    console.print(f"[bold]RedTeam v{__version__}[/] target={target} type={ttype}")
    console.print(f"[cyan]Plan ({len(plan.nodes)} nodes):[/] " + " → ".join(n.phase for n in plan.nodes))

    if dry_run:
        console.print("[yellow]--dry-run: plan only, no attacks executed[/]")
        return

    # Execute (MVP: step through nodes, record via HTTP client + sandbox)
    http = RedTeamHTTP(guard=guard, read_only=read_only)
    if auth_header:
        name, _, value = auth_header.partition(":")
        if not value.strip():
            console.print("[red]--auth-header 需為 'Name: value' 形式(例 'Authorization: Bearer ***[/]")
            raise typer.Exit(1)
        http.default_headers[name.strip()] = value.strip()
        console.print(f"[cyan]Auth header:{name.strip()} <value redacted>[/]")
    if read_only:
        console.print("[bold yellow]READ-ONLY 模式:僅安全方法(GET/HEAD/OPTIONS)可離網;"
                      "sqlmap/ZAP full/api 將被拒絕[/]")
    sandbox = DockerSandbox(timeout=cfg.runtime.get("llm_timeout", 30))
    report = ReportGenerator(target, ttype)

    # Resolve scanner set for this run
    if scanners == "auto":
        scanners = "llm_playbook" if ttype == "llm_app" else "all"
    if scanners not in ("none", "llm_playbook", "nuclei", "sqlmap", "zap", "all", "web_config"):
        console.print(f"[red]Unknown --scanners value: {scanners}[/]")
        raise typer.Exit(1)

    scan_results: dict[str, Any] = {}
    # Scanner set banner (web_config 為純本地探測,其餘 web 掃描器需 Docker)
    if scanners == "all":
        console.print("[cyan]Scanner set: all (web_config + nuclei + sqlmap + zap)[/]")
    elif scanners in ("nuclei", "sqlmap", "zap"):
        console.print(f"[cyan]Scanner set: {scanners}[/]")
    elif scanners == "llm_playbook":
        console.print("[cyan]Scanner set: llm_playbook (LLM attack playbooks)[/]")
    elif scanners == "web_config":
        console.print("[cyan]Scanner set: web_config(純本地組態探測,不需 Docker)[/]")

    for node in plan.nodes:
        if node.status == "completed":
            continue
        node.status = "in_flight"
        console.print(f"[cyan]▸ {node.id} {node.phase} ({node.action})[/]")

        # Phase-specific behavior:
        #   recon / fingerprint -> HTTP probing for web, headers for llm_app
        #   inject (web) -> run scanners (full scan)
        #   verify -> if inject found anything, re-run judge verify on them;
        #             else skip (no duplicates). (llm) -> playbook payloads (TBD)
        if node.phase in ("inject", "verify") and scanners in ("all", "nuclei", "sqlmap", "zap", "llm_playbook", "web_config"):
            # verify phase: the final _judge_and_report() at the end of the run
            # already runs the LLM judge over all captured findings, so verify
            # must NOT re-run scanners/playbooks or a second (throwaway) judge
            # pass — that was double token spend + double probes against the
            # target (review fix).
            is_verify = node.phase == "verify"
            if is_verify:
                if scan_results:
                    console.print("  [cyan]verify: findings already captured; LLM judge runs at end of run[/]")
                    node.result = {"verify": True, "findings": len(scan_results)}
                else:
                    console.print("  [dim]verify: no findings from inject, nothing to verify[/]")
                    node.result = {"verify": True, "findings": 0}
            elif scanners == "llm_playbook":
                # LLM attack playbooks against an OpenAI-compatible endpoint.
                # target is treated as the chat/completions base URL.
                if not _guard_ok(guard, target):
                    console.print(f"[red]ScopeGuard: target {target} outside authorized scope → skipped[/]")
                    node.result = {"scan": False, "blocked": True}
                else:
                    from .playbook import PlaybookLoader, PlaybookEngine, LLMTarget, load_playbooks

                    judge_cfg = cfg.llm.get("judge", {})
                    model = (judge_cfg.get("model") or "gpt-4o")
                    lt = LLMTarget(
                        guard=guard,
                        base_url=target,
                        model=model,
                        timeout=cfg.runtime.get("llm_timeout", 30),
                        max_tokens=cfg.runtime.get("llm_max_tokens", 512),
                        rate_qps=cfg.runtime.get("rate_limit_qps", 10),
                        auth_header=auth_header,
                        read_only=read_only,
                    )
                    pbs = load_playbooks(os.environ.get("REDTEAM_PLAYBOOK_DIR", "playbooks/llm"),
                                          single=playbook)
                    results = []
                    authorized = guard.is_authorized() if guard else False
                    budget = cfg.runtime.get("token_budget", 500_000)
                    tokens_spent = 0
                    for pb in pbs:
                        # Safety gate: side-effect playbooks (e.g. LLM03 tool-call,
                        # LLM06 consumption) require an authorized credential.
                        if not pb.get("side_effect_free", True) and not authorized:
                            console.print(
                                f"  [dim]{pb.get('id')} {pb.get('name')}: "
                                f"requires authorization (side_effect_free=false) → skipped[/]"
                            )
                            continue
                        engine = PlaybookEngine(lt, max_probes=pb.get("max_probes", 30))
                        try:
                            prs = engine.run(pb)
                            hits = [r for r in prs if r.passed]
                            results += prs
                            tokens_spent += sum(
                                (r.usage or {}).get("total_tokens", 0)
                                for r in prs
                            )
                            if tokens_spent > budget:
                                console.print(f"  [red]token budget exceeded ({budget}) → stopping playbooks[/]")
                                break
                            if hits:
                                console.print(
                                    f"  [green]{pb.get('id')} {pb.get('name')}: "
                                    f"{len(hits)} probe(s) confirmed[/]"
                                )
                            elif prs and all(r.blocked_by_scope for r in prs):
                                # 全部探測被擋(read-only/scope)時不得顯示
                                # 「guardrails held」— 那會被誤讀為已驗證防禦有效
                                # (同 nuclei 靜默零覆蓋教訓)。
                                console.print(
                                    f"  [yellow]{pb.get('id')} {pb.get('name')}: "
                                    f"all probes BLOCKED (read-only/scope) — "
                                    f"未實際觸達目標,不構成任何結論[/]"
                                )
                            else:
                                console.print(
                                    f"  [dim]{pb.get('id')} {pb.get('name')}: "
                                    f"no attack confirmed (guardrails held)[/]"
                                )
                        except Exception as e:  # noqa: BLE001
                            console.print(f"    [red]playbook {pb.get('id')} failed: {e}[/]")
                    if results:
                        scan_results["llm_playbook"] = results
                        node.result = {"scan": True, "probes": len(results),
                                       "confirmed": sum(1 for r in results if r.passed)}
                    else:
                        node.result = {"scan": True, "probes": 0}
            else:
                # inject phase. ScopeGuard mandatory for all probing paths.
                # web_config 走 RedTeamHTTP(逐請求檢查);Docker 掃描器繞過
                # HTTP client,故在此顯式檢查 scope(網路政策在 _exec 內強制)。
                if not _guard_ok(guard, target):
                    console.print(f"[red]ScopeGuard: scan target {target} outside authorized scope → skipped[/]")
                    node.result = {"scan": False, "blocked": True}
                else:
                    # M5:web_config 先行 —— 純本地確定性組態探測,
                    # 不需 Docker、不需 LLM,一律經 RedTeamHTTP(ScopeGuard 在位)。
                    if scanners in ("all", "web_config"):
                        from .web_config import WebConfigProbe

                        wc_probes = WebConfigProbe(http=http).run(target)
                        wc_hits = sum(1 for r in wc_probes if r.passed)
                        scan_results["web_config"] = wc_probes
                        console.print(
                            f"    [green]web_config:{wc_hits} 個組態弱點"
                            f"(共 {len(wc_probes)} 檢查項)[/]"
                        )

                    # --cve-watch:從目標 HTML 找 <pkg>@<ver> 指紋宣告,
                    # 查 GHSA 列適用未修 CVE(2026-09-18 n8n 實務需求產品化)。
                    # GHSA 查詢走 api.github.com(非靶點),對目標零額外流量。
                    if cve_watch:
                        from .version_watch import detect_releases, watch

                        try:
                            body = http.request("GET", target).body or b""
                        except Exception:  # noqa: BLE001
                            body = b""
                        releases = detect_releases(body.decode("utf-8", "replace"))
                        if not releases:
                            console.print("    [dim]cve-watch:指紋未發現 <pkg>@<ver> 宣告[/]")
                        watch_results = []
                        for name, ver in releases:
                            # ecosystem 猜測:含點號的 scoped 名稱與 JS 慣例 → npm;
                            # 可用 REDTEAM_CVE_ECOSYSTEM 覆寫(例 "pip")
                            eco = os.environ.get("REDTEAM_CVE_ECOSYSTEM", "npm")
                            wr = watch(name, eco, ver)
                            if wr.error:
                                console.print(f"    [yellow]cve-watch {name}@{ver}:{wr.error}[/]")
                                continue
                            watch_results.append(wr)
                            if wr.matches:
                                console.print(
                                    f"    [red]cve-watch {name}@{ver}:"
                                    f"{len(wr.matches)} 個適用未修 CVE"
                                    f"(最高 {wr.highest_severity},"
                                    f"修復版 {wr.matches[0].first_patched or '?'})[/]"
                                )
                            else:
                                stale = (f"  [dim](資料源最新公告 {wr.latest_advisory_date},"
                                         "廠商公告可能有數天同步滯後)[/]"
                                         if wr.latest_advisory_date else "")
                                console.print(
                                    f"    [green]cve-watch {name}@{ver}:無適用 CVE[/]{stale}"
                                )
                        if watch_results:
                            scan_results["version_watch"] = watch_results

                    # M5:Docker 型掃描器在 docker 不可用時優雅跳過(明確警告,不 crash)
                    names = _scanner_names(scanners)
                    if names and not _docker_available():
                        console.print(
                            "[yellow]警告:偵測不到 docker → 略過 Docker 型掃描器"
                            "(nuclei/sqlmap/zap);僅 web_config 結果可用[/]"
                        )
                        names = []

                    if names:
                        job_timeout = cfg.runtime.get("job_timeout", 1800)
                        if zap_mode != "baseline":
                            # full/api scans need more headroom (opencode review)
                            job_timeout = max(job_timeout, ScannerBridge.ZAP_MODE_TIMEOUT.get(zap_mode, 1800))
                        bridge = ScannerBridge(timeout=job_timeout, read_only=read_only)
                        for scope_name in names:
                            console.print(f"  [cyan]▶ running {scope_name}...[/]")
                            try:
                                if scope_name == "nuclei":
                                    job = bridge.nuclei_runner(
                                        target,
                                        severity=nuclei_severity,
                                        exclude_protocols=nuclei_exclude_protocols,
                                    )
                                elif scope_name == "sqlmap":
                                    job = bridge.sqlmap_runner(target)
                                else:
                                    job = bridge.zap_api_scan(target, mode=zap_mode, api_format=zap_api_format)
                                asyncio.run(bridge.start(job))
                                if job.status == "failed" and job.result is None and job.stderr:
                                    console.print(f"    [red]{scope_name}: {job.stderr.strip().splitlines()[-1]}[/]")
                                if job.result:
                                    scan_results[scope_name] = job.result
                                    console.print(f"    [green]{scope_name}: {_summarize_result(job.result)}[/]")
                                elif job.status == "completed":
                                    console.print(f"    [yellow]{scope_name}: no findings[/]")
                            except Exception as e:  # noqa: BLE001
                                console.print(f"    [red]scanner {scope_name} failed: {e}[/]")
                    node.result = {"scan": True, "results": list(scan_results.keys())}
        else:
            try:
                rec = http.request("GET", target)
                report.records.append(rec)
                if rec.blocked_by_scope:
                    console.print(f"[red]ScopeGuard: blocked request to {target}[/]")
                    node.result = {"blocked": True}
                else:
                    node.result = {"status": rec.status} if rec.status else {"blocked": True}
                    console.print(f"  HTTP {rec.status or 'blocked'} ({len(rec.body or b'')} bytes)")
            except Exception as e:  # noqa: BLE001
                console.print(f"[red]request failed: {e}[/]")
                node.result = {"error": str(e)}
        node.status = "completed"

    # Save checkpoint
    ck = store.save(plan)
    console.print(f"[green]Checkpoint saved: {ck}[/]")

    # If any scanner produced results, run them through judge + findings into report
    if scan_results:
        _judge_and_report(target, scan_results, config_path=config_path, full=full)
    else:
        out = report.write()
        console.print(f"[bold green]Report: {out}[/]")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL"),
    scanner: str = typer.Option("nuclei", "--scanner", "-s", help="nuclei|sqlmap|zap|all"),
    templates: Optional[str] = typer.Option(None, "--templates", "-t", help="nuclei template (hash-verified)"),
    tags: Optional[str] = typer.Option(None, "--tags", help="nuclei tags filter"),
    auth_cred: Optional[str] = typer.Option(None, "--auth-cred", help="Signed JWS credential"),
    public_key: Optional[str] = typer.Option(None, "--public-key", help="Issuer Ed25519 public key (PEM)"),
    network: Optional[str] = typer.Option(None, "--network", help="Docker network for egress"),
    timeout: int = typer.Option(900, "--timeout", help="scan job timeout seconds"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="config.yaml path"),
    full: bool = typer.Option(False, "--full", help="Disable redaction (requires auth credential)"),
    zap_mode: str = typer.Option("baseline", "--zap-mode", help="ZAP scan mode: baseline|full|api (default baseline; full=active SQLi/XSS/SSRF scanning)"),
    zap_api_format: Optional[str] = typer.Option(None, "--zap-api-format", help="ZAP api mode format: openapi|soap|graphql (required when --zap-mode api)"),
    nuclei_severity: Optional[str] = typer.Option(None, "--nuclei-severity", help="nuclei -severity (default: low,medium,high,critical; pass '' to disable filter)"),
    nuclei_exclude_protocols: Optional[str] = typer.Option(None, "--nuclei-exclude-protocols", help="nuclei -exclude-protocols (default: dns,code,file,websocket,whois; pass '' to disable)"),
    read_only: bool = typer.Option(False, "--read-only", help="生產環境保險絲:sqlmap/ZAP full-api 直接拒絕,nuclei 限速(掃描器繞過 HTTP 客戶端,方法封鎖靠憑證 methods)"),
):
    """Run scanner(s) (nuclei/sqlmap/zap/all) against target in Docker sandbox."""
    scanners = ["nuclei", "sqlmap", "zap"] if scanner == "all" else [scanner]
    for s in scanners:
        if s not in ("nuclei", "sqlmap", "zap"):
            console.print(f"[red]Unknown scanner: {s}[/]")
            raise typer.Exit(1)

    # Scope enforcement: strict localhost-only unless valid credential
    try:
        guard = _load_guard(auth_cred, public_key)
    except RuntimeError as e:
        console.print(f"[red]Authorization: {e}[/]")
        raise typer.Exit(1)
    if guard.is_authorized():
        console.print("[green]Loaded credential: verified[/]")
    elif not _is_localhost(target):
        console.print("[red]Scan target outside localhost requires --auth-cred + --public-key (signed credential).[/]")
        raise typer.Exit(1)
    if full and not guard.is_authorized():
        console.print("[red]--full (disable redaction) requires a signed credential.[/]")
        raise typer.Exit(1)

    # Explicit guard check for credentialed AND localhost paths (Docker bypasses HTTP)
    if not _guard_ok(guard, target):
        console.print(f"[red]ScopeGuard: {target} outside authorized scope → blocked.[/]")
        raise typer.Exit(1)

    if zap_mode != "baseline":
        # full/api scans need more headroom, same as `run` (agy review)
        timeout = max(timeout, ScannerBridge.ZAP_MODE_TIMEOUT.get(zap_mode, 900))
    bridge = ScannerBridge(network=network, timeout=timeout, read_only=read_only)
    results: dict[str, Any] = {}
    if scanner == "all":
        console.print("[bold cyan]Running all scanners (nuclei + sqlmap + zap)...[/]")
        for s in scanners:
            if s == "nuclei":
                job = bridge.nuclei_runner(
                    target, templates=templates, tags=tags,
                    severity=nuclei_severity, exclude_protocols=nuclei_exclude_protocols,
                )
            elif s == "sqlmap":
                job = bridge.sqlmap_runner(target)
            else:
                job = bridge.zap_api_scan(target, mode=zap_mode, api_format=zap_api_format)
            console.print(f"[cyan]▶ {s} job {job.job_id}[/]")
            asyncio.run(bridge.start(job))
            _report_job(job)
            if job.result:
                results[s] = job.result
    else:
        if scanner == "nuclei":
            job = bridge.nuclei_runner(
                target, templates=templates, tags=tags,
                severity=nuclei_severity, exclude_protocols=nuclei_exclude_protocols,
            )
        elif scanner == "sqlmap":
            job = bridge.sqlmap_runner(target)
        else:
            job = bridge.zap_api_scan(target, mode=zap_mode, api_format=zap_api_format)
        console.print(f"[cyan]▶ {scanner} job {job.job_id}: {job.args}[/]")
        asyncio.run(bridge.start(job))
        _report_job(job)
        if job.result:
            results[scanner] = job.result

    # Convert scanner output -> Findings, then LLM judge, then report
    _judge_and_report(target, results, config_path=config_path, full=full)


def _judge_and_report(target: str, results: dict[str, Any], *, config_path: str | None = None,
                      full: bool = False) -> None:
    """Turn raw scanner results into Findings, run LLM judge for false-positive
    triage, and emit a Markdown report (spec §6.4 / §11).

    Runs exactly once per execution (verify phase no longer triggers a second
    pass — review fix: was double LLM token spend with throwaway results).
    """
    from .findings import Finding as ScannerFinding, convert_all

    cfg = Config.load(config_path)
    findings = convert_all(results)
    console.print(f"[bold cyan]Converted {len(findings)} scanner findings[/]")

    # LLM judge second pass (deterministic params; skipped if unconfigured)
    judge_cfg = cfg.llm.get("judge", {})
    judge = LLMJudge(judge_cfg)
    llm_available = judge.available
    if not llm_available:
        console.print("[yellow]LLM judge not configured → using deterministic filter only (confidence preserved)[/]")
    triaged: list[ScannerFinding] = []
    for f in findings:
        if f.source == "web_config":
            # M5:web_config 為純確定性證據(confidence=1.0),
            # 不需 LLM judge 二次確認 —— 直接保留進報告。
            triaged.append(f)
            console.print(f"  [cyan]= {f.id} {f.title} [deterministic(免 LLM 複核)][/]")
            continue
        # exfil 證據一併送審(反幻覺:宣稱的擷取物必須逐字可核)。
        # 預算控制(agy review):judge.confirm 對 evidence 有 [:2000] 硬截斷,
        # 先削觀察證據到 1400,宣稱段限 5 筆×200 字,避免宣稱段被截半
        # ——截碎片會與觀察證據 verbatim 比對失敗,真的漏洞被誤殺成幻覺。
        obs_evidence = (f.evidence or "")[:1400]
        claims = getattr(f, "extracted", None)
        if claims:
            claim_block = "\n".join(f"- {str(x)[:200]}" for x in claims[:5])[:500]
            judge_evidence = f"{obs_evidence}\n\nExtracted data claimed:\n{claim_block}"
        else:
            judge_evidence = obs_evidence
        text = judge.confirm(
            evidence=judge_evidence,
            suspect=f"{f.title} ({f.category}) at {target}",
        )
        verdict = judge.verdict(text)
        if verdict == "confirmed":
            f.confidence = min(f.confidence + 0.1, 1.0)
            triaged.append(f)
            console.print(f"  [green]✓ {f.id} {f.title} [CONFIRMED][/]")
        elif verdict == "refuted":
            console.print(f"  [dim]✗ {f.id} {f.title} [refuted by judge][/]")
        elif text is None:
            # LLM unavailable (no key/base_url configured): keep scanner confidence
            triaged.append(f)
            console.print(f"  [dim]• {f.id} {f.title} [deterministic only][/]")
        else:
            f.confidence = f.confidence * 0.5  # uncertain -> lower confidence
            triaged.append(f)
            console.print(f"  [yellow]? {f.id} {f.title} [UNCERTAIN][/]")

    # Emit report from surviving findings
    redact_mode = "full" if full else "auto"
    report = ReportGenerator(target, _detect_target_type(target), redact_mode=redact_mode)
    for f in triaged:
        report.add_finding(
            Finding(
                id=f.id,
                attack_surface=f.attack_surface,
                category=f.category,
                severity=f.severity,
                title=f.title,
                description=f.description,
                steps=f.steps,
                poc=f.poc,
                confidence=f.confidence,
                fp_risk=f.fp_risk,
                owasp=getattr(f, "owasp", ""),  # P1:carry OWASP class into report
                # M6:帶上 CVSS(此前 convert_all 算好的分數在 bridge 處被丟棄,
                # 報告永遠顯示 0.0 — 這是既有的接線 bug,一併修復)
                cvss_score=getattr(f, "cvss_score", 0.0),
                cvss_vector=getattr(f, "cvss_vector", ""),
                # exfil 閉環:nuclei extracted-results 等真實擷取物隨 finding 過橋,
                # 由下方 attach_exfil() 登錄進報告 §3
                extracted=list(getattr(f, "extracted", None) or []),
            )
        )
    report.attach_exfil()
    n_exfil = len(report.exfiltrated)
    out = report.write()
    if n_exfil:
        console.print(f"[yellow]§3 偷到的資料:登錄 {n_exfil} 筆"
                      f"{'(已自動脫敏;--full 可保留原樣)' if not full else '(--full:未脫敏!)'}[/]")
    # agy review:含高危自動評分時明確警示「未定稿」(防 CI 把草稿當正式報告發布;
    # exit code 保持 0 — 報告產出本身成功,門禁由狀態行與警示承擔)
    unreviewed = [f for f in triaged if (f.severity or "").lower() in ("high", "critical")]
    if unreviewed:
        console.print(
            f"[yellow]注意:報告含 {len(unreviewed)} 項高危/嚴重發現,CVSS 為自動推導評分,"
            f"定稿前須經人工複核(草稿)[/]"
        )
    console.print(f"[bold green]Report: {out}[/]")


def _guard_ok(guard: ScopeGuard | None, target: str) -> bool:
    """ScopeGuard check for scanner targets (Docker path bypasses HTTP client).
    Returns True when target is permitted by scope / localhost-only default."""
    if guard is None:
        return True
    from urllib.parse import urlparse

    u = urlparse(target)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    return guard.check(host, port, u.path or "/", "GET")


def _is_localhost(target: str) -> bool:
    """Strict localhost check (no DNS-rebinding-style prefix tricks)."""
    from urllib.parse import urlparse

    u = urlparse(target)
    host = (u.hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "::1", "example.com"):
        return True
    # 127.0.0.0/8 loopback CIDR
    import ipaddress

    try:
        ip = ipaddress.ip_address(host)
        return ip in ipaddress.ip_network("127.0.0.0/8") or ip in ipaddress.ip_network("::1/128")
    except Exception:
        return False


def _scanner_names(scanners: str) -> list[str]:
    """Expand scanner selector to a concrete list of Docker-based scanner names.

    web_config 不是 Docker 掃描器(純 Python、走 RedTeamHTTP),回傳空清單;
    它的執行路徑在 run() 的 inject 分支另行處理。"""
    if scanners == "all":
        return ["nuclei", "sqlmap", "zap"]
    if scanners == "web_config":
        return []
    return [scanners]


def _docker_available() -> bool:
    """偵測 docker CLI 是否存在且 daemon 可用(M5:無 Docker 環境優雅降級)。

    只檢查 CLI 存在是不夠的(docker 二進位可能在但 daemon 沒跑),
    故再打一次 `docker version` 確認 server 端可達。"""
    import shutil
    import subprocess

    if shutil.which("docker") is None:
        return False
    try:
        proc = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            timeout=5,
        )
        return proc.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _summarize_result(result: Any) -> str:
    """Compact summary of a scanner result dict/list."""
    if isinstance(result, list):
        return f"{len(result)} findings"
    if isinstance(result, dict) and "alerts" in result:
        return f"{result.get('warn', 0)} warn, {result.get('fail', 0)} fail"
    if isinstance(result, dict) and "raw" in result:
        return "sqlmap output captured"
    return "results captured"


def _report_job(job) -> None:
    """Print a scanner job's outcome compactly."""
    console.print(f"  [cyan]Status: {job.status}[/]")
    if job.result:
        if isinstance(job.result, list):
            console.print(f"  [green]nuclei findings: {len(job.result)}[/]")
            for f in job.result[:5]:
                console.print(f"    - {f.get('info', {}).get('name', '?')} [{f.get('severity', '?')}] {f.get('matched-at', '')}")
        elif isinstance(job.result, dict) and "alerts" in job.result:
            console.print(f"  [green]ZAP: {job.result['warn']} warn, {job.result['fail']} fail[/]")
            for a in job.result["alerts"][:8]:
                console.print(f"    - {a}")
        elif isinstance(job.result, dict) and "raw" in job.result:
            console.print(f"  [green]sqlmap: {job.result['raw'][:300]}[/]")
    if job.stdout and not job.result:
        console.print("  " + job.stdout[:500])
    if job.stderr and "INF" not in job.stderr[:500]:
        console.print(f"  [yellow]{job.stderr[:500]}[/]")


@app.command()
def cve(
    query: str = typer.Argument(..., help="CVE ID( CVE-2025-55182 )或產品名( django / laravel/framework / n8n )"),
    ecosystem: Optional[str] = typer.Option(None, "--ecosystem", "-e", help="npm|pip|composer|maven|go|cargo|rubygems(產品級查詢用)"),
    version: Optional[str] = typer.Option(None, "--version", "-v", help="只列影響此版本的 CVE(產品級)"),
    json_out: bool = typer.Option(False, "--json", help="輸出 JSON(供工具鏈)"),
):
    """直查 CVE:GHSA + OSV + NVD 三源。CVE ID 精確查,產品名列全部已發布 CVE。"""
    from .cve_lookup import lookup

    is_cve = re.match(r"(?i)^CVE-\d{4}-\d{4,7}$", query.strip())
    res = lookup(cve_id=query.strip().upper() if is_cve else None,
                 product=None if is_cve else query,
                 ecosystem=ecosystem, version=version)
    if not res.ok:
        console.print(f"[red]{res.error}[/]")
        raise typer.Exit(1)
    if json_out:
        console.print_json(json.dumps({
            "query": res.query, "sources": res.sources,
            "latest_advisory_date": res.latest_advisory_date,
            "advisories": [vars(a) for a in res.advisories]}, ensure_ascii=False))
        return
    console.print(f"[bold]CVE lookup[/] {res.query} [dim]sources: {', '.join(res.sources) or '—'}[/]")
    if not res.advisories:
        console.print("[yellow]查無適用 CVE — 注意:GHSA/NVD 對廠商公告有數天滯後,"
                      f"資料源最新公告 {res.latest_advisory_date or '未知'};查無 ≠ 無漏洞[/]")
        return
    from rich.markup import escape
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    for a in sorted(res.advisories, key=lambda x: (order.get(x.severity, 5), x.cve)):
        color = {"critical": "red", "high": "red", "medium": "yellow"}.get(a.severity, "dim")
        rng = f" [{escape(a.vulnerable_range)}]" if a.vulnerable_range else ""
        patched = f" → 修復 {a.first_patched}" if a.first_patched else ""
        prod = f"({escape(a.product)})" if a.product else ""
        console.print(f"  [{color}]{a.cve:<18}[/] [{color}]{escape(a.severity)}[/] "
                      f"{prod}{rng}{patched} [dim]{escape(a.summary[:90])}[/]")
    console.print(f"[dim]共 {len(res.advisories)} 筆,最新公告 {res.latest_advisory_date or '未知'}。"
                  "動態嘗試請用 tanli agent 或 tanli scan --tags <CVE-ID>[/]")


@app.command()
def agent(
    target: str = typer.Argument(..., help="授權目標 URL"),
    goal: str = typer.Option("", "--goal", "-g", help="評估目標(預設:雙軌全面評估)"),
    steps: int = typer.Option(30, "--steps", help="自主循環最大步數"),
    probes: int = typer.Option(60, "--probes", help="HTTP 探測硬預算"),
    token_budget: int = typer.Option(200_000, "--token-budget", help="LLM token 預算"),
    auth_cred: Optional[str] = typer.Option(None, "--auth-cred", help="Signed JWS credential file"),
    public_key: Optional[str] = typer.Option(None, "--public-key", help="Issuer Ed25519 public key (PEM)"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="config.yaml path"),
    full: bool = typer.Option(False, "--full", help="Disable redaction (requires auth credential)"),
    read_only: bool = typer.Option(False, "--read-only", help="生產保險絲:物理封鎖非安全方法"),
    auth_header: Optional[str] = typer.Option(None, "--auth-header", help="附加標頭,值絕不進報告"),
    no_docker: bool = typer.Option(False, "--no-docker", help="不給 nuclei 動態嘗試能力"),
    roe_file: Optional[str] = typer.Option(None, "--roe", help="Rules of Engagement YAML(tanli roe --init 產生)"),
    workspace_dir: str = typer.Option("workspaces", "--workspace",
                                      help="engagement 工作區目錄(跨會話記憶+大輸出卸載);'none' 關閉"),
):
    """自主 Agent 模式:LLM tool-loop 自行規劃多步驟探測(指紋→產品級CVE→動態嘗試)。

    與 run 的差別:run 走固定 DAG;agent 讓 LLM 自己決定每步(像 OpenCode/Hermes
    的 tool loop),但所有工具都在 ScopeGuard/read-only/預算圍籬內,模型繞不過。
    """
    from .agent import AgentTools, OpenAIBrain, run_agent
    from .engagement import (RoE, build_opplan, detect_target_type,
                             save_engagement_package)
    from .workspace import Workspace

    cfg = Config.load(config_path)
    try:
        guard = _load_guard(auth_cred, public_key)
    except RuntimeError as e:
        console.print(f"[red]Authorization: {e}[/]")
        raise typer.Exit(1)
    if guard.is_authorized():
        console.print("[green]Signed credential loaded and verified[/]")
    else:
        console.print("[yellow]No credential → localhost-only scope enforced[/]")
        if full:
            console.print("[red]--full (disable redaction) requires a signed credential.[/]")
            raise typer.Exit(1)

    http = RedTeamHTTP(guard=guard, read_only=read_only,
                       timeout=cfg.runtime.get("web_timeout", 60))
    if auth_header:
        name, _, value = auth_header.partition(":")
        if not value.strip():
            console.print("[red]--auth-header 需為 'Name: value' 形式[/]")
            raise typer.Exit(1)
        http.default_headers[name.strip()] = value.strip()
        console.print(f"[cyan]Auth header: {name.strip()} <value redacted>[/]")
    if read_only:
        console.print("[bold yellow]READ-ONLY 模式:非安全方法物理封鎖[/]")

    bridge = None
    if not no_docker and _docker_available():
        bridge = ScannerBridge(timeout=cfg.runtime.get("job_timeout", 1800), read_only=read_only)
    elif not no_docker:
        console.print("[yellow]無 Docker → nuclei_cve_probe 動態嘗試不可用(agent 會如實回報)[/]")

    # ---- 作戰紀律包(借鑑 Decepticon):先定紀律,再放行 ----
    roe = RoE.load(roe_file)
    ws = None
    if workspace_dir.lower() != "none":
        ws = Workspace.open(target, base=workspace_dir)
    target_type = detect_target_type(goal or target)
    opplan = build_opplan(target_type, roe)
    brief_parts = [roe.as_prompt_block(), opplan]
    if ws is not None:
        mem_block = ws.memory_prompt_block()
        if mem_block:
            brief_parts.append(mem_block)
        console.print(f"[cyan]工作區: {ws.root}(跨會話記憶啟用)[/]")
    engagement_brief = "\n\n".join(brief_parts)
    pkg_path = save_engagement_package(
        ws.root if ws else Path("state"), target, roe, opplan)
    console.print(f"[cyan]Engagement package: {pkg_path}[/]")

    tools = AgentTools(http, target, docker_bridge=bridge, workspace=ws)
    tools.max_probes = probes
    try:
        brain = OpenAIBrain(cfg.llm.get("judge", {}))
    except (RuntimeError, ImportError) as e:
        console.print(f"[red]Agent brain 不可用:{e}[/]")
        raise typer.Exit(1)

    console.print(f"[bold cyan]自主 Agent 啟動[/] target={target} steps≤{steps} "
                  f"probes≤{probes} tokens≤{token_budget}")
    result = run_agent(tools, brain,
                       goal=goal or ("雙軌安全評估:識別真實元件/框架 → 產品級 CVE 核實 → "
                                     "動態嘗試確認;記錄所有有證據的發現"),
                       max_steps=steps, token_budget=token_budget, console=console,
                       engagement_brief=engagement_brief)
    console.print(f"[bold]Agent 完成[/] steps={result.steps} probes={result.probes} "
                  f"tokens={result.tokens} finished={result.finished}")
    if result.summary:
        console.print(f"[italic]{result.summary[:600]}[/]")

    from .findings import Finding
    from .report import ReportGenerator
    report = ReportGenerator(target, "hybrid", redact_mode="full" if full else "auto")
    # 報告按 triage 風險分排序(借鑑 CypherFix:高 likelihood 先修)
    ordered = sorted(result.findings,
                     key=lambda f: (f.triage_score, f.confidence), reverse=True)
    for i, f in enumerate(ordered, 1):
        # agent finding → 標準 Finding(CVSS 由 annotate_cvss 就地標注)
        from .cvss import annotate_cvss
        triage_note = (f" (triage={f.triage_score}"
                       + (f" kev={f.kev}" if f.kev else "") + ")") if f.triage_score >= 0 else ""
        fd = Finding(
            id=f"agent-{i:02d}", attack_surface="hybrid",
            category=f.category + (f":{f.cve}" if f.cve else ""),
            severity=f.severity, title=f.title + triage_note,
            description=f.description,
            steps=["autonomous agent loop"], poc=f.evidence[:1500] or None,
            confidence=f.confidence,
            evidence=f.evidence[:2000], source="agent", owasp="A06" if f.cve else "",
            # agent 經 add_finding.exfiltrated_data 登錄的擷取物過橋 → §3
            extracted=list(getattr(f, "exfiltrated", None) or []),
        )
        annotate_cvss([fd])
        report.add_finding(fd)
    # exfil 閉環:把各 finding 的 extracted 逐筆登錄進 §3(自動走 redact 脫敏;
    # 未傳 --full 時金鑰/JWT/Bearer 一律遮蔽)
    n_exfil = report.attach_exfil()
    out = report.write()
    console.print(f"[bold green]Report: {out}[/]")
    if n_exfil:
        console.print(f"[yellow]§3 偷到的資料:登錄 {n_exfil} 筆"
                      f"{'(已自動脫敏;--full 可保留原樣)' if not full else '(--full:未脫敏)'}[/]")
    ck = Path("state") / f"agent_transcript_{int(time.time())}.json"
    ck.parent.mkdir(exist_ok=True)
    ck.write_text(json.dumps(result.transcript, ensure_ascii=False, indent=1))
    console.print(f"[dim]Transcript: {ck}[/]")


@app.command()
def roe(
    init: Optional[str] = typer.Option(None, "--init", help="在指定路徑產生 RoE YAML 範本"),
    show: Optional[str] = typer.Option(None, "--show", help="預覽既有 RoE 檔的 prompt 注入效果"),
):
    """作戰紀律(RoE)管理:產生範本 / 預覽 agent 將看到的紀律宣告。"""
    from .engagement import RoE, new_roe_template
    if init:
        p = new_roe_template(init)
        console.print(f"[green]RoE 範本: {p}[/] 依實際授權範圍編輯後用 --roe 指定")
        return
    if show:
        r = RoE.load(show)
        console.print(r.as_prompt_block())
        return
    console.print("[yellow]用法: tanli roe --init roe.yaml 或 tanli roe --show roe.yaml[/]")


@app.command()
def gen_cred(
    scope: str = typer.Argument(..., help="scope.yaml with targets"),
    key: str = typer.Option(..., "--key", "-k", help="Ed25519 private key PEM (signer)"),
    out: str = typer.Option("credential.jws", "--out", "-o"),
    kid: str = typer.Option("redteam-1", "--kid"),
    ttl: int = typer.Option(86400, "--ttl", help="credential TTL seconds"),
):
    """Issue a signed authorization credential (JWS)."""
    import yaml

    data = yaml.safe_load(Path(scope).read_text())
    statement = ScopeStatement(
        authorized_by=data.get("authorized_by", "unknown"),
        production=bool(data.get("production", False)),
        targets=[ScopeEntry(**t) for t in data.get("targets", [])],
        allowed_out_of_band=data.get("allowed_out_of_band", []),
    )
    token = sign_credential(statement, Path(key).read_text(), kid, ttl)
    Path(out).write_text(token)
    console.print(f"[green]Credential written: {out}[/]")


@app.command()
def self_test():
    """Run benchmark self-test (spec §9.9):本地靶場 + web_config 端到端驗證。

    全程不需要 Docker、不需要外部網路(僅 127.0.0.1)、不需要 LLM API key
    (web_config finding 走純確定性路徑,不經 LLM judge)。
    """
    from .findings import convert_all
    from .target_lab import TargetLab
    from .web_config import WebConfigProbe

    failures: list[str] = []

    def _check(ok: bool, label: str, detail: str = "") -> None:
        if ok:
            console.print(f"[green][PASS][/] {label}")
        else:
            msg = f"[red][FAIL][/] {label}"
            if detail:
                msg += f" — {detail}"
            console.print(msg)
            failures.append(label)

    console.print("[cyan]self-test:啟動本地靶場(TargetLab,127.0.0.1 隨機 port)...[/]")
    root_findings: list = []
    with TargetLab() as lab:
        base = lab.base_url
        # localhost-only 預設範圍即可覆蓋 127.0.0.1(不需任何憑證)
        http = RedTeamHTTP(guard=ScopeGuard(None))
        probe = WebConfigProbe(http=http)

        # 斷言 1:對 / 探測應產生 >= 4 個 finding
        # (CSP / XFO / XCTO / Referrer-Policy 缺失 + cookie 屬性)
        root_probes = probe.run(base)
        root_findings = convert_all({"web_config": root_probes})
        _check(
            len(root_findings) >= 4,
            f"不安全首頁產生 >= 4 個 finding",
            f"實際 {len(root_findings)} 個:"
            + ", ".join(f"{f.title}[{f.severity}]" for f in root_findings),
        )

        # 斷言 2:所有 finding 的 OWASP 欄位都有值(非空)
        empty_owasp = [f"{f.id}:{f.title}" for f in root_findings if not f.owasp]
        _check(
            not empty_owasp,
            "所有 finding 的 OWASP 欄位皆有值",
            f"空值:{empty_owasp}",
        )

        # 斷言 3:對 /secure 探測 → 0 個 medium/critical(加固頁不得誤報)
        secure_probes = probe.run(base, paths=["/secure"])
        secure_findings = convert_all({"web_config": secure_probes})
        loud = [
            f"{f.id}:{f.title}[{f.severity}]"
            for f in secure_findings
            if f.severity in ("medium", "critical")
        ]
        _check(not loud, "加固頁(/secure)無 medium/critical 誤報", f"誤報:{loud}")

        # 斷言 4:渲染報告 → 含 OWASP 2021 聚合段且 A05 有計數
        report = ReportGenerator(base, "web_service")
        for f in root_findings:
            report.add_finding(
                Finding(
                    id=f.id,
                    attack_surface=f.attack_surface,
                    category=f.category,
                    severity=f.severity,
                    title=f.title,
                    description=f.description,
                    steps=f.steps,
                    poc=f.poc,
                    confidence=f.confidence,
                    fp_risk=f.fp_risk,
                    owasp=getattr(f, "owasp", ""),
                    cvss_score=getattr(f, "cvss_score", 0.0),
                    cvss_vector=getattr(f, "cvss_vector", ""),
                )
            )
        rendered = report.render()
        has_agg = "## 5. OWASP 2021 覆蓋度聚合" in rendered and "| A05 |" in rendered
        _check(has_agg, "報告含 OWASP 2021 聚合段(A05)")

    # ------------------------------------------------------------------
    # M6:LLM playbook 端到端(vulnerable/hardened 靶場)+ CVSS/修復建議驗證
    # 全程 127.0.0.1、無 Docker、無 LLM API key
    # ------------------------------------------------------------------
    from .playbook import LLMTarget, PlaybookEngine, load_playbooks

    pb_path = (
        Path(__file__).resolve().parent
        / "playbooks" / "llm" / "playbook_1.yaml"
    )
    llm_findings: list = []
    try:
        pbs = load_playbooks(single=str(pb_path))
        pb = pbs[0]
    except Exception as e:  # noqa: BLE001
        _check(False, "載入 playbook_1.yaml", str(e))
        pb = None

    if pb is not None:
        # 斷言 5:vulnerable 靶場 → playbook_1 應確認 >=1 個 LLM finding
        with TargetLab(behavior="vulnerable") as lab2:
            lt = LLMTarget(ScopeGuard(None), lab2.base_url, model="redteam-lab", rate_qps=50)
            engine = PlaybookEngine(lt, max_probes=pb.get("max_probes", 30))
            probe_results = engine.run(pb)
            llm_findings = convert_all({"llm_playbook": probe_results})
        bad_owasp = [f"{f.id}:{f.owasp}" for f in llm_findings if not f.owasp.startswith("LLM")]
        bad_surface = [f.id for f in llm_findings if f.attack_surface != "llm"]
        bad_cvss = [f.id for f in llm_findings if not f.cvss_score > 0]
        _check(
            len(llm_findings) >= 1
            and not bad_owasp and not bad_surface and not bad_cvss,
            "vulnerable LLM 靶場 → >=1 個 finding(LLMxx/llm surface/CVSS>0)",
            f"共 {len(llm_findings)} 個; owasp 異常 {bad_owasp}; surface 異常 {bad_surface}; cvss 異常 {bad_cvss}",
        )

        # 斷言 6:hardened 靶場 → 0 個 finding(典範目標不誤報)
        hardened_findings: list = []
        with TargetLab(behavior="hardened") as lab3:
            lt3 = LLMTarget(ScopeGuard(None), lab3.base_url, model="redteam-lab", rate_qps=50)
            engine3 = PlaybookEngine(lt3, max_probes=pb.get("max_probes", 30))
            hardened_findings = convert_all({"llm_playbook": engine3.run(pb)})
        _check(
            not hardened_findings,
            "hardened LLM 靶場 → 0 個 finding(不誤報)",
            f"誤報 {[f'{f.id}:{f.title}' for f in hardened_findings]}",
        )

        # 斷言 7:報告渲染 → 含 CVSS 向量與實質修復建議(非佔位文字)
        full_report = ReportGenerator("http://127.0.0.1/self-test", "hybrid")
        for f in (root_findings + llm_findings):
            full_report.add_finding(
                Finding(
                    id=f.id,
                    attack_surface=f.attack_surface,
                    category=f.category,
                    severity=f.severity,
                    title=f.title,
                    description=f.description,
                    steps=f.steps,
                    poc=f.poc,
                    confidence=f.confidence,
                    fp_risk=f.fp_risk,
                    owasp=getattr(f, "owasp", ""),
                    cvss_score=getattr(f, "cvss_score", 0.0),
                    cvss_vector=getattr(f, "cvss_vector", ""),
                )
            )
        rendered_full = full_report.render()
        sec6 = rendered_full.split("## 6. 修復建議", 1)[-1] if "## 6. 修復建議" in rendered_full else ""
        has_vector = "CVSS:3.1/" in rendered_full
        has_advice = ("本次無發現" not in sec6) and len(sec6.strip()) > 20 and "-" in sec6
        _check(
            has_vector and has_advice,
            "報告含 CVSS v3.1 向量與實質修復建議",
            f"向量={has_vector} 建議={has_advice}",
        )

        # 斷言 8:exfil 閉環 —— 靶場 /canary 真實擷取 → 報告 §3 逐字出現,
        # 且假 sk- 金鑰被 redact 遮罩(auto 模式)。hardened 面 /canary 必須 403
        # (典範目標無擷取路徑)。全離線、無 LLM:走 add_exfil 的確定性通道。
        canary_body = ""
        with TargetLab(behavior="vulnerable") as lab4:
            r4 = RedTeamHTTP(guard=ScopeGuard(None)).request(
                "GET", lab4.base_url + "/canary")
            canary_body = (r4.body or b"").decode("utf-8", "replace")
        exfil_report = ReportGenerator("http://127.0.0.1/self-test", "hybrid")
        exfil_report.add_finding(
            Finding(
                id="f-exfil-01", attack_surface="web", category="info_disclosure",
                severity="high", title="exfil 閉環驗證",
                description="canary 擷取 → §3",
                steps=["GET /canary"],
                extracted=[canary_body],
            )
        )
        n_logged = exfil_report.attach_exfil()
        # 冪等:重複調用不得重複登錄
        n_again = exfil_report.attach_exfil()
        rendered_exfil = exfil_report.render()
        sec3 = rendered_exfil.split("## 3.", 1)[-1].split("## 4.", 1)[0]
        # /canary 的哨兵必須逐字進 §3;假金鑰中段必須被遮罩成 ****
        # (canary 兩行 → attach_exfil 依行拆成 2 條登錄)
        ok_canary = "REDTEAM_EXFIL_CANARY_9f3a" in sec3
        ok_redact = "sk-demo****1234" in sec3 and "00000000000000000000000" not in sec3
        ok_count = n_logged == 2 and n_again == 0
        hardened_blocked = False
        with TargetLab(behavior="hardened") as lab5:
            r5 = RedTeamHTTP(guard=ScopeGuard(None)).request(
                "GET", lab5.base_url + "/canary")
            hardened_blocked = r5.status == 403
        _check(
            ok_canary and ok_redact and ok_count and hardened_blocked,
            "exfil 閉環:擷取物進 §3 + 金鑰遮罩 + 冪等 + hardened /canary 403",
            f"哨兵={ok_canary} 遮罩={ok_redact} 冪等={ok_count} 熔斷={hardened_blocked}",
        )

    if failures:
        console.print(f"[red]self-test 失敗:{len(failures)} 項[/]")
        raise typer.Exit(1)
    console.print(f"[bold green]self-test 全部通過({__version__})[/]")


def main():
    app()


if __name__ == "__main__":
    main()

