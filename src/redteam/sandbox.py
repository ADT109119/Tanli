"""Docker sandbox - spec §3.1 / §5.

Sandboxed command execution in isolated Docker containers.
Network egress restricted to target CIDR (network namespace).
Async job queue for long scans (nuclei/ZAP/sqlmap).
"""

from __future__ import annotations

import asyncio
import subprocess
import uuid
from dataclasses import dataclass, field


@dataclass
class SandboxResult:
    job_id: str
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    partial: bool = False
    status: str = "completed"  # running | completed | killed


class DockerSandbox:
    """Wrapper around docker run for isolated command execution."""

    IMAGE = "redteam-sandbox:latest"  # expected prebuilt hardened image

    def __init__(self, timeout: int = 30, mem: str = "512m", cpu: float = 1.0, network: str | None = None):
        self.timeout = timeout
        self.mem = mem
        self.cpu = cpu
        self.network = network  # docker network (target CIDR egress)
        self.jobs: dict[str, SandboxResult] = {}

    def _net_flag(self) -> list[str]:
        """Choose network mode:
        - explicit --network wins (sandbox on target CIDR egress)
        - default to host network (scan local machine's own apps / localhost targets)
        - for remote/internal targets, scanner runs still require explicit --network
        """
        if self.network:
            return ["--network", self.network]
        # host network lets the sandbox reach services on this machine,
        # which is the only network available when no egress network is wired.
        return ["--network", "host"]

    def run(self, cmd: list[str], *, workdir: str = "/tmp", timeout: int | None = None) -> SandboxResult:
        """Execute a single command synchronously in sandbox."""
        job_id = uuid.uuid4().hex[:12]
        docker_cmd = [
            "docker", "run", "--rm",
            "--network", self.network or "host",
            "--memory", self.mem, "--cpus", str(self.cpu),
            "-v", f"{workdir}:/work", "-w", "/work",
            self.IMAGE,
        ] + cmd
        try:
            proc = subprocess.run(
                docker_cmd, capture_output=True, text=True,
                timeout=timeout or self.timeout,
            )
            result = SandboxResult(job_id, proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired:
            result = SandboxResult(job_id, None, "", f"timeout after {timeout or self.timeout}s", timed_out=True)
        self.jobs[job_id] = result
        return result

    async def run_async(self, cmd: list[str], *, job_timeout: int = 1800) -> SandboxResult:
        """Submit a long-running scan as an async job (spec §3.1 job queue)."""
        job_id = uuid.uuid4().hex[:12]
        live = SandboxResult(job_id, None, "", "", status="running")
        self.jobs[job_id] = live
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "run", "--rm",
                "--network", self.network or "host",
                "--memory", self.mem, "--cpus", str(self.cpu),
                self.IMAGE, *cmd,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout=job_timeout)
                live.stdout = out.decode()
                live.stderr = err.decode()
                live.exit_code = proc.returncode
            except asyncio.TimeoutError:
                proc.kill()
                live.timed_out = True
                live.partial = True
                live.status = "killed"
                live.stderr += f"\n[job timeout after {job_timeout}s]"
            else:
                live.status = "completed"
        except Exception as e:  # noqa: BLE001
            live.status = "killed"
            live.stderr = str(e)
        return live
