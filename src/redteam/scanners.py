"""Scanner bridge - spec §3.2 / §3.1.

Scanners (nuclei/sqlmap/ZAP) are invoked through isolated Docker containers,
never directly on the host. Each scanner gets:
- network isolated (target-related network or none)
- resource caps (memory/cpu)
- hash-verified templates (nuclei)
- async job queue for long scans (spec §3.1)

GPL tools (sqlmap) are called via subprocess/container only (spec §7.1).
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .sandbox import DockerSandbox

# Official/community hardened images per scanner
IMAGES = {
    "nuclei": "projectdiscovery/nuclei:latest",
    "sqlmap": "ilyaglow/sqlmap:latest",
    "zap": "ghcr.io/zaproxy/zaproxy:latest",
}


@dataclass
class ScannerJob:
    scanner: str
    job_id: str
    args: list[str]
    status: str = "queued"  # queued | running | completed | failed | killed
    result: Any = None
    stdout: str = ""
    stderr: str = ""
    created_at: float = 0.0
    finished_at: float | None = None
    mode: str = "baseline"  # ZAP scan mode: baseline | full | api (P2)
    target: str | None = None  # original (pre-rewrite) target URL


def target_is_local(target: str) -> bool:
    """True when target points at the local machine (host-network scan is OK)."""
    from ipaddress import ip_address, ip_network
    from urllib.parse import urlparse

    u = urlparse(target if "://" in target else f"http://{target}")
    host = (u.hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True
    try:
        ip = ip_address(host)
        return ip in ip_network("127.0.0.0/8") or ip in ip_network("::1/128")
    except ValueError:
        return False


# Container hardening applied to every scanner container (spec §3.1):
# drop all Linux capabilities, forbid privilege escalation, cap pids.
HARDENING = ["--cap-drop", "ALL",
             "--security-opt", "no-new-privileges:true",
             "--pids-limit", "512"]


class ScannerBridge:
    """Orchestrates scanner execution through Docker sandboxes."""

    def __init__(
        self,
        sandbox: DockerSandbox | None = None,
        network: str | None = None,
        timeout: int = 1800,
        read_only: bool = False,
    ):
        self.sandbox = sandbox or DockerSandbox(network=network, timeout=timeout)
        self.network = network
        self.read_only = read_only
        self.jobs: dict[str, ScannerJob] = {}
        self._queue: asyncio.Queue = asyncio.Queue()

    # ---------- runner commands (docker run wrappers) ----------

    #: P3 限縮預設:排除 info 級噪音(ZAP/web_config 已覆蓋資訊類發現)
    NUCLEI_DEFAULT_SEVERITY = "low,medium,high,critical"
    #: 排除不適用 web 靶點的協議(保留 http/https/ssl,不影響 A02 TLS 覆蓋)
    NUCLEI_DEFAULT_EXCLUDE_PROTOCOLS = "dns,code,file,websocket,whois"

    def nuclei_runner(self, target: str, *, templates: str | None = None, tags: str | None = None,
                      severity: str | None = None, exclude_protocols: str | None = None) -> ScannerJob:
        """Run nuclei scan. Templates must be hash-verified (spec §5.2).

        `templates` may be a template file or directory path. (The earlier
        bare `--update-template-dir` flag was removed: it takes a value and,
        left dangling, made nuclei exit with 'flag needs an argument'.)

        P3 限縮(降誤報+提速):
        - `severity`: None → 用預設(排除 info 級);傳空字串 → 不加此參數(全收)
        - `exclude_protocols`: None → 用預設(dns/code/file/websocket/whois,
          保留 http/ssl 以免 A02 TLS 覆蓋倒退);傳空字串 → 不排除
        """
        args = ["-u", target]
        if templates:
            args += ["-t", templates]
        if tags:
            args += ["-tags", tags]
        if severity is None:
            severity = self.NUCLEI_DEFAULT_SEVERITY
        if severity:
            args += ["-severity", severity]
        if exclude_protocols is None:
            exclude_protocols = self.NUCLEI_DEFAULT_EXCLUDE_PROTOCOLS
        if exclude_protocols:
            # nuclei v3 將協議過濾改名為 -exclude-type(-ept);舊名 -exclude-protocols
            # 已不存在,傳舊名會讓 nuclei 直接 exit「flag provided but not defined」
            # (2026-09-18 生產環境實測發現)
            args += ["-exclude-type", exclude_protocols]
        if self.read_only:
            # read-only:nuclei 無「僅安全方法」開關(模板可宣告 POST),故以
            # 限速 10/s 降低對生產環境的負載;真正的方法封鎖由外層
            # ScopeGuard methods(憑證範疇)把關 — 掃描器繞過 HTTP 客戶端,
            # 呼叫端務必確認 scope methods 只含 GET/HEAD/OPTIONS。
            args += ["-rl", "10"]
        args += ["-jsonl", "-irr"]
        return self._submit("nuclei", args)

    def sqlmap_runner(self, url: str, *, level: int = 1, risk: int = 1, batch: bool = True) -> ScannerJob:
        """Run sqlmap via Docker (GPL tool, subprocess boundary only - spec §7.1)."""
        if self.read_only:
            raise ValueError(
                "read-only 模式禁止 sqlmap:主動注入探測會向目標發出 POST 與"
                "高載請求,可能觸發寫入/鎖表 — 生產環境請改用被動掃描"
            )
        args = ["-u", url, "--batch", "--level", str(level), "--risk", str(risk)]
        return self._submit("sqlmap", args)

    def zap_api_scan(self, target: str, *, auth: str | None = None, mode: str = "baseline",
                     api_format: str | None = None) -> ScannerJob:
        """Run OWASP ZAP scan (headless DAST).

        mode:
          - baseline (default): zap-baseline.py — passive checks + light spider.
          - full: zap-full-scan.py — active scan incl. SQLi/XSS/SSRF 探測 (P2).
          - api: zap-api-scan.py — API/GraphQL focused scan (P2).

        Notes (opencode + agy review 2026-08):
          - full/api-scan 的 -s = "short output, hide PASS lines", 不是主動開關.
            主動探測是 full-scan 內建行爲 (spider -> active scan).
          - full-scan 的 spider 預設無上限, 必須加 -m <min> 分鐘限制
            與 -T <min> 啓動等待限制, 防止 container timeout (partial).
          - -I: 忽略告警退出碼 (否則 WARN 會讓腳本以非 0 退出).
          - api 模式 (zap-api-scan.py) 必須配 -f openapi|soap|graphql,
            否則腳本直接報錯退出 (agy review).
          - 需要更多記憶體/timeout: full 模式建議 job_timeout >= 3600s.

        Uses the official image's zap-<mode>.py entrypoint.
        """
        if mode not in ("baseline", "full", "api"):
            raise ValueError(f"Unknown ZAP mode: {mode!r} (baseline|full|api)")
        if self.read_only and mode in ("full", "api"):
            raise ValueError(
                f"read-only 模式禁止 ZAP {mode} 模式:主動掃描會發出探測"
                "payload(POST/變體參數) — 生產環境請用 --zap-mode baseline"
            )
        # entrypoint 由 _exec 按 job.mode 決定 (zap-baseline/full/api-scan.py)
        args = ["-t", target, "-J", "zap-report.json"]
        if mode == "full":
            # -s: short output (hide PASS details). -m/-T bound the scan so the
            # sandbox timeout only acts as a last-resort fuse. -I: WARN no longer
            # makes the script exit non-zero.
            # NOTE: -m = active scan max minutes, -T = spider max minutes (BOTH
            # minutes, not seconds). Keep -m 30 + -T 10 (total ~40m) under the
            # 3600s full-mode timeout so the scan finishes before being killed.
            args += ["-s", "-I", "-m", "30", "-T", "10"]
        if mode == "api":
            # zap-api-scan.py REQUIRES -f (openapi|soap|graphql); fail fast
            # instead of letting the container crash (agy review).
            if not api_format or api_format not in ("openapi", "soap", "graphql"):
                raise ValueError(
                    f"api_format ('openapi'|'soap'|'graphql') is required when mode='api', got {api_format!r}"
                )
            args += ["-f", api_format]
        if auth:
            args += ["-a", auth]
        job = self._submit("zap", args)
        job.mode = mode  # record for report description
        return job

    # full/API scans push ZAP to use more resources; expose a suggested timeout
    ZAP_MODE_TIMEOUT: dict[str, int] = {"baseline": 900, "full": 3600, "api": 1800}

    # ---------- job lifecycle (async queue, spec §3.1) ----------

    def _submit(self, scanner: str, args: list[str]) -> ScannerJob:
        # Remember the ORIGINAL target (before the host.docker.internal
        # rewrite) so _exec can apply the network policy correctly.
        flag = "-t" if scanner == "zap" else "-u"
        target = next((args[i] for i in range(1, len(args)) if args[i - 1] == flag), None)
        # Rewrite localhost targets to host.docker.internal for in-container reach
        args = [self._rewrite_localhost(a) for a in args]
        job = ScannerJob(
            scanner=scanner,
            job_id=uuid.uuid4().hex[:12],
            args=args,
            created_at=time.time(),
            target=target,
        )
        self.jobs[job.job_id] = job
        return job

    @staticmethod
    def _rewrite_localhost(arg: str) -> str:
        """WSL/Docker: 127.0.0.1/localhost inside a container points at the
        container itself. Rewrite to host.docker.internal so the scanner can
        reach services bound on the host's loopback. Preserves scheme."""
        for alias in ("http://127.0.0.1", "https://127.0.0.1", "http://localhost", "https://localhost"):
            if arg.startswith(alias):
                rest = arg[len(alias):]
                return f"https://host.docker.internal{rest}" if alias.startswith("https") else f"http://host.docker.internal{rest}"
        return arg

    @staticmethod
    def _select_nuclei_template_dir(templates: Path) -> str | None:
        """依模板目錄內容決定 nuclei -t 的容器內路徑(可單測,不需 docker)。

        - <templates>/http/ 存在且含 yaml → /workspace/templates/http
          (P3 限縮:官方 nuclei-templates checkout 的 HTTP 協議子目錄,
           排除 dns/iot/cloud 等不適用 web 靶點的模板 → 提速+降誤報)
        - 否則根目錄含 yaml → /workspace/templates(全量掛載)
        - 空目錄 → None(不加 -t,走 nuclei 內建模板;呼叫端須警告)
        """
        http_dir = templates / "http"
        if http_dir.is_dir() and (
            any(http_dir.rglob("*.yaml")) or any(http_dir.rglob("*.yml"))
        ):
            return "/workspace/templates/http"
        if any(templates.rglob("*.yaml")) or any(templates.rglob("*.yml")):
            return "/workspace/templates"
        return None

    async def _exec(self, job: ScannerJob) -> None:
        """Execute one job in the sandbox (async)."""
        job.status = "running"
        image = IMAGES.get(job.scanner, "busybox:latest")
        # docker run --rm <hardening> --network <net> --memory --cpus <image> <args>
        cmd = ["docker", "run", "--rm", *HARDENING]
        # Network policy (spec §3.1: egress restricted to target network):
        #  - explicit --network always wins (operator-wired target CIDR net);
        #  - local (127.0.0.0/8 / localhost) targets: host network so the
        #    container reaches the host's loopback services;
        #  - remote targets REQUIRE an explicit egress network — a blind
        #    host-network container for a signed remote target would let the
        #    scanner (or any container compromise) reach the whole host net.
        if self.network:
            cmd += ["--network", self.network]
        elif target_is_local(job.target or ""):
            cmd += ["--network", "host"]
        else:
            job.status = "failed"
            job.stderr = (
                f"remote target {job.target!r} requires an explicit egress network: "
                f"re-run with --network <docker-network> "
                "(spec §3.1 egress restriction; host network is only for local targets)"
            )
            job.finished_at = time.time()
            return
        # WSL/Docker Desktop: allow container to reach host's localhost services
        cmd += ["--add-host", "host.docker.internal:host-gateway"]
        if job.scanner == "nuclei":
            # Mount templates dir if present (hash-verified templates - spec §5.2)
            templates = Path(
                os.environ.get("REDTEAM_NUCLEI_TEMPLATES", "/tmp/redteam-nuclei-templates")
            )
            templates.mkdir(exist_ok=True)
            cmd += ["-v", f"{templates}:/workspace/templates"]
            # Only mount -t when the dir actually contains templates. An empty
            # default dir (fresh machine) would make nuclei load ZERO templates
            # and silently report "no findings" (false sense of security).
            # P3 限縮:若存在官方 nuclei-templates 的 http/ 子目錄(含 yaml),
            # 優先把 -t 指向 /workspace/templates/http — 只跑 HTTP 協議模板,
            # 排除 dns/iot/cloud 等不適用 web 靶點的模板(提速+降誤報)。
            # 掛載點仍是 templates 根目錄(http/ 是其子目錄,容器內可見)。
            if "-t" not in job.args and "--templates" not in job.args and templates.exists():
                chosen = self._select_nuclei_template_dir(templates)
                if chosen:
                    job.args += ["-t", chosen]
                else:
                    job.stderr += (
                        "\n[nuclei] template dir is empty → using nuclei built-in "
                        "templates (set REDTEAM_NUCLEI_TEMPLATES to a "
                        "nuclei-templates checkout for full coverage)"
                    )
        if job.scanner == "zap":
            # ZAP needs more memory + uses zap-<mode>.py as entrypoint,
            # and requires /zap/wrk mounted for report output (-J)
            wrk = Path(os.environ.get("REDTEAM_ZAP_WRK", "/tmp/redteam-zap-wrk"))
            wrk.mkdir(exist_ok=True)
            # Remove any stale zap-report.json so a crashed/timeout scan cannot
            # feed old findings into this run (agy review: report pollution).
            (wrk / "zap-report.json").unlink(missing_ok=True)
            script = {
                "baseline": "zap-baseline.py",
                "full": "zap-full-scan.py",
                "api": "zap-api-scan.py",
            }.get(getattr(job, "mode", "baseline"), "zap-baseline.py")
            cmd += [
                "--memory", "2g",
                "-v", f"{wrk}:/zap/wrk",
                "--entrypoint", script,
            ]
        cmd += [image] + job.args
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=self.sandbox.timeout)
            job.stdout = out.decode()
            job.stderr = err.decode()
            job.finished_at = time.time()
            if job.scanner == "nuclei" and job.stdout.strip():
                job.result = self._parse_nuclei_jsonl(job.stdout)
            elif job.scanner == "sqlmap":
                # Keep the TAIL of the output: sqlmap prints its verdict
                # ("is vulnerable", parameter list) at the END of the run, so
                # a head-truncation could silently drop the finding.
                job.result = {"raw": job.stdout[-4000:]}
            elif job.scanner == "zap":
                wrk = Path(os.environ.get("REDTEAM_ZAP_WRK", "/tmp/redteam-zap-wrk"))
                job.result = self._parse_zap_summary(
                    job.stdout, json_path=str(wrk / "zap-report.json")
                )
                if job.result:
                    # record the mode so reports can say full vs baseline (P2)
                    job.result["mode"] = getattr(job, "mode", "baseline")
            # ZAP baseline exits 1 when it finds alerts - still a successful scan.
            has_alerts = (
                job.scanner == "zap"
                and job.result
                and (job.result["warn"] > 0 or job.result["fail"] > 0)
            )
            job.status = "completed" if (has_alerts or (proc and proc.returncode == 0)) else "failed"
        except asyncio.TimeoutError:
            # Spec §3.1: on timeout, kill and mark partial (not a hard failure),
            # preserving any partial output collected so far.
            job.status = "partial"
            if proc:
                proc.kill()
                try:
                    await asyncio.wait_for(proc.communicate(), timeout=5)
                except Exception:  # noqa: BLE001
                    pass  # already dead or unresponsive; avoid zombie
            # Keep whatever output was captured (communicate timed out, so empty;
            # but the marker lets the caller know scanning was cut short).
            job.stderr += "\n[scanner job timeout - partial]"
            job.finished_at = time.time()
        except Exception as e:  # noqa: BLE001
            job.status = "failed"
            job.stderr = str(e)

    async def start(self, job: ScannerJob) -> None:
        """Submit and immediately execute (single-job mode)."""
        await self._exec(job)

    async def run_all(self, jobs: list[ScannerJob]) -> list[ScannerJob]:
        """Run multiple jobs concurrently."""
        await asyncio.gather(*[self._exec(j) for j in jobs])
        return list(self.jobs.values())

    @staticmethod
    def _parse_nuclei_jsonl(stdout: str) -> list[dict]:
        """Parse nuclei -jsonl output into structured findings."""
        findings = []
        for line in stdout.strip().splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return findings

    @staticmethod
    def _load_zap_tags_report(json_path: str) -> dict[str, list[str]]:
        """Load zap-report.json (written into /zap/wrk) and map alert-id -> tags.

        ZAP's official jsonreport includes per-alert 'tags' containing OWASP
        Top Ten categories (opencode review: prefer these over hardcoded ids).
        Returns {alert_id: [tags...]}; {} when the file is absent/unreadable.
        """
        import json as _json
        from pathlib import Path as _Path

        p = _Path(json_path)
        if not p.exists():
            return {}
        try:
            data = _json.loads(p.read_text())
        except (OSError, ValueError):
            return {}
        out: dict[str, list[str]] = {}
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                aid = str(alert.get("pluginid", ""))
                if aid:
                    out.setdefault(aid, []).extend(alert.get("tags", []) or [])
        return out

    @staticmethod
    def _parse_zap_summary(stdout: str, json_path: str | None = None) -> dict:
        """Parse ZAP baseline summary line plus any WARN-NEW alert lines.

        When json_path points at a zap-report.json, attach official tags from
        it per alert-id so downstream OWASP mapping can prefer ZAP's own tags.
        """
        import re

        tags_by_id: dict[str, list[str]] = {}
        if json_path:
            tags_by_id = ScannerBridge._load_zap_tags_report(json_path)
        summary = {"alerts": [], "fail": 0, "warn": 0, "pass": 0, "raw_tail": stdout[-1500:], "tags_by_id": tags_by_id}
        m = re.search(r"FAIL-NEW: (\d+)\s+FAIL-INPROG: \d+\s+WARN-NEW: (\d+)", stdout)
        if m:
            summary["fail"] = int(m.group(1))
            summary["warn"] = int(m.group(2))
        for line in stdout.splitlines():
            if "WARN-NEW" in line or "FAIL-NEW" in line:
                summary["alerts"].append(line.strip())
        return summary
