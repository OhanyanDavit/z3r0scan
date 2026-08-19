"""Small shared helpers: tool detection, subprocess wrapper, target parsing."""

from __future__ import annotations

import ipaddress
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


def resolve(host: str) -> str | None:
    """Resolve a hostname to an IPv4 address, or None on failure."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None
