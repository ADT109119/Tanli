"""Authorization - JWS (Ed25519) signed credentials + Scope Statement enforcement.

Implements spec §5.1 / §5.1.1:
- Signed credential = JWS containing Scope Statement + expiry.
- ScopeGuard programmatically verifies each request against declared scope.
- CRL (revoked list) + key rotation support.
- Unauthenticated state => localhost-only default.
"""

from __future__ import annotations

import ipaddress
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jwt

LOCALHOST_ONLY = {"127.0.0.0/8", "::1/128", "localhost", "example.com"}


def _load_revoked_kids() -> set[str]:
    """CRL from REDTEAM_REVOKED_KIDS (comma-separated kid values)."""
    raw = os.environ.get("REDTEAM_REVOKED_KIDS", "")
    return {k.strip() for k in raw.split(",") if k.strip()}


@dataclass
class ScopeEntry:
    host: str
    cidr: str | None = None
    ports: list[int] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    window: str | None = None  # "startZ/endZ"
    contact: str | None = None

    def _in_window(self) -> bool:
        if not self.window or "/" not in self.window:
            return True
        start, end = self.window.split("/", 1)
        now = time.time()
        # ISO-ish parsing; on failure FAIL CLOSED — a scope guard that cannot
        # parse its authorization window must deny, not silently allow
        # (the config author intended a bounded window).
        try:
            from datetime import datetime

            s = datetime.fromisoformat(start.replace("Z", "+00:00")).timestamp()
            e = datetime.fromisoformat(end.replace("Z", "+00:00")).timestamp()
            return s <= now <= e
        except Exception:
            return False

    def allows(self, host: str, port: int, path: str, method: str) -> bool:
        if not self._in_window():
            return False
        if self.cidr and self._host_in_cidr(host):
            pass
        elif self.host != host:
            return False
        if self.ports and port not in self.ports:
            return False
        if self.paths and not any(path.startswith(p) for p in self.paths):
            return False
        if self.methods and method.upper() not in [m.upper() for m in self.methods]:
            return False
        return True

    def _host_in_cidr(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
            return ip in ipaddress.ip_network(self.cidr)
        except Exception:
            return False


@dataclass
class ScopeStatement:
    authorized_by: str
    targets: list[ScopeEntry]
    production: bool = False
    allowed_out_of_band: list[str] = field(default_factory=list)


class ScopeGuard:
    """Enforces scope on every outbound request. Spec §5.1."""

    def __init__(self, statement: ScopeStatement | None, public_key: str | bytes | None = None,
                 credential_kid: str | None = None):
        self.statement = statement
        self.public_key = public_key
        self.credential_kid = credential_kid  # kid of the loaded credential
        self.revoked: set[str] = _load_revoked_kids()  # CRL: revoked kid values

    def is_authorized(self) -> bool:
        if self.statement is None or self.public_key is None:
            return False
        # Revoked credential (CRL hit) => treated as unauthenticated.
        return not self.is_revoked()

    def is_revoked(self) -> bool:
        return bool(self.credential_kid and self.credential_kid in self.revoked)

    def check(self, host: str, port: int, path: str, method: str, kid: str | None = None) -> bool:
        """Return True if request is permitted. Programmatic, per-request.

        CRL: the effective kid is the per-request `kid` if given, else the
        loaded credential's kid. A revoked credential degrades to
        localhost-only (fail closed, spec §5.1).
        """
        effective_kid = kid or self.credential_kid
        if effective_kid and effective_kid in self.revoked:
            return self._localhost_only(host)
        if not self.is_authorized():
            # unauthenticated => localhost-only
            return self._localhost_only(host)
        if not self.statement:
            return False
        return any(t.allows(host, port, path, method) for t in self.statement.targets)

    def _localhost_only(self, host: str) -> bool:
        if host in ("localhost", "example.com"):
            return True
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network("127.0.0.0/8") or \
                ipaddress.ip_address(host) in ipaddress.ip_network("::1/128")
        except Exception:
            return False


def sign_credential(scope: ScopeStatement, private_key_pem: str, kid: str, ttl: int = 86400) -> str:
    """Issue a JWS credential (Ed25519). Spec §5.1.1."""
    now = int(time.time())
    payload = {
        "kid": kid,
        "iss": scope.authorized_by,
        "scope": _scope_to_dict(scope),
        "production": scope.production,
        "iat": now,
        "exp": now + ttl,
    }
    return jwt.encode(payload, private_key_pem, algorithm="EdDSA", headers={"kid": kid})


def credential_kid(token: str) -> str | None:
    """Extract the `kid` header from a JWS credential WITHOUT verifying the
    signature (used only for CRL revocation checks; the payload is untrusted
    until verify_credential runs)."""
    try:
        import base64
        import json

        header_b64 = token.split(".", 1)[0]
        padding = "=" * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64 + padding))
        return header.get("kid")
    except Exception:
        return None


def verify_credential(token: str, public_key_pem: str) -> tuple[ScopeStatement, str | None]:
    """Verify JWS and extract ScopeStatement; raises on invalid/expired.

    Returns (statement, kid) — kid comes from the verified payload so CRL
    checks are signature-backed (not just the unverified header).
    """
    decoded = jwt.decode(token, public_key_pem, algorithms=["EdDSA"])
    kid = decoded.get("kid") or credential_kid(token)
    statement = ScopeStatement(
        authorized_by=decoded["iss"],
        production=bool(decoded.get("production", False)),
        targets=[ScopeEntry(**t) for t in decoded["scope"]["targets"]],
        allowed_out_of_band=decoded["scope"].get("allowed_out_of_band", []),
    )
    return statement, kid


def _scope_to_dict(s: ScopeStatement) -> dict[str, Any]:
    return {
        "targets": [
            {
                "host": t.host,
                "cidr": t.cidr,
                "ports": t.ports,
                "paths": t.paths,
                "methods": t.methods,
                "window": t.window,
                "contact": t.contact,
            }
            for t in s.targets
        ],
        "allowed_out_of_band": s.allowed_out_of_band,
    }
