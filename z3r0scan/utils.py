"""Small shared helpers: tool detection, subprocess wrapper, target parsing."""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
from urllib.parse import urlparse


def have_tool(name: str) -> bool:
    """Return True if an external binary is on PATH."""
    return shutil.which(name) is not None


def run(cmd: list[str], timeout: float = 120.0, input_text: str | None = None) -> tuple[int, str, str]:
    """Run a command, capturing output. Never raises on non-zero exit.

    Optionally feeds ``input_text`` to the process's stdin. Returns
    (returncode, stdout, stderr). A missing binary or timeout is reported as
    returncode -1 with the reason in stderr.
    """
    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, "", f"binary not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", f"timed out after {timeout}s"


def normalize_host(target: str) -> str:
    """Strip scheme/path from a target, leaving a bare hostname or IP."""
    target = target.strip()
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    # host:port or bare host
    if target.count(":") == 1 and not is_ipv6(target):
        return target.split(":")[0]
    return target


def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_ipv6(target: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(target), ipaddress.IPv6Address)
    except ValueError:
        return False


def resolve_all(host: str) -> list[str]:
    """Resolve a hostname to all its IPs (IPv4 first, then IPv6). Empty on failure.

    Uses ``getaddrinfo`` so IPv6-only hosts resolve too — ``gethostbyname`` only
    ever returned an A record and silently dropped AAAA-only targets.
    """
    host = (host or "").strip()
    if not host:
        return []
    if is_ip(host):
        return [host]
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, socket.herror, OSError, UnicodeError):
        return []
    v4, v6 = [], []
    for family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if family == socket.AF_INET6 and ip not in v6:
            v6.append(ip)
        elif family == socket.AF_INET and ip not in v4:
            v4.append(ip)
    return v4 + v6


def resolve(host: str) -> str | None:
    """Resolve a hostname to a single IP (IPv4 preferred), or None on failure."""
    ips = resolve_all(host)
    return ips[0] if ips else None


# Characters that must never appear in a target we hand to a subprocess or URL.
_CONTROL_CHARS = ("\x00", "\r", "\n", "\t")
_SECRET_QS = re.compile(
    r"([?&](?:key|apikey|api_key|token|access_token|secret|password)=)[^&\s]+", re.IGNORECASE
)


class TargetError(ValueError):
    """Raised when a target string is unsafe or malformed."""


def validate_target(target: str) -> str:
    """Return a cleaned target or raise :class:`TargetError`.

    This is a safety boundary, not cosmetic normalization. It rejects empty
    values, embedded control characters, and option-like strings (leading ``-``)
    that a tool such as nmap could interpret as a flag rather than a target
    (argument-list subprocesses stop shell injection, not option injection). It
    also range-checks an explicit ``host:port``.
    """
    t = (target or "").strip()
    if not t:
        raise TargetError("empty target")
    if any(c in t for c in _CONTROL_CHARS):
        raise TargetError("target contains control characters")
    if " " in t:
        raise TargetError("target may not contain spaces")
    if t.startswith("-"):
        raise TargetError("target may not start with '-' (looks like a CLI option)")

    host = normalize_host(t)
    if not host or host.startswith("-"):
        raise TargetError("invalid target host")

    # Validate an explicit port when present (host:port, not bare IPv6/URL host).
    if "://" not in t and t.count(":") == 1 and not is_ipv6(t):
        _h, _sep, port = t.partition(":")
        if port and port.isdigit():
            if not (1 <= int(port) <= 65535):
                raise TargetError(f"port out of range: {port}")
        elif port:
            raise TargetError(f"invalid port: {port}")
    return t


def redact(text: str, *secrets: str) -> str:
    """Strip known secrets and secret-looking query params from user-facing text.

    Used before any exception string or URL reaches a report, so an API key
    passed as a query parameter (e.g. Shodan) can never leak into JSON/HTML/logs.
    """
    if not text:
        return text
    out = text
    for secret in secrets:
        if secret and len(secret) >= 4:
            out = out.replace(secret, "***REDACTED***")
    return _SECRET_QS.sub(r"\1***REDACTED***", out)
