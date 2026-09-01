"""Small shared helpers: tool detection, subprocess wrapper, target parsing."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
from urllib.parse import urlparse


def have_tool(name: str) -> bool:
    """Return True if an external binary is on PATH."""
    return shutil.which(name) is not None


def _terminate(proc: subprocess.Popen) -> None:
    """Kill a process and its whole group (started with start_new_session)."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            return
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            pass


def run(
    cmd: list[str],
    timeout: float = 120.0,
    input_text: str | None = None,
    cancel_event: "threading.Event | None" = None,
) -> tuple[int, str, str]:
    """Run a command, capturing output. Never raises on non-zero exit.

    Optionally feeds ``input_text`` to the process's stdin. Returns
    (returncode, stdout, stderr). A missing binary, timeout, or cancellation is
    reported as returncode -1 with the reason in stderr.

    When ``cancel_event`` is provided and gets set mid-run, the process (and its
    child group) is terminated promptly so a long scan can be interrupted; any
    output captured so far is still returned. The process is launched in its own
    session so tools that fork children (nmap, nuclei) are killed as a group.
    """
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except FileNotFoundError:
        return -1, "", f"binary not found: {cmd[0]}"

    # Drain pipes in background threads so a chatty process can't deadlock on a
    # full pipe buffer while we poll for completion/cancellation.
    out_chunks: list[str] = []
    err_chunks: list[str] = []

    def _drain(pipe, sink):
        try:
            for line in iter(pipe.readline, ""):
                sink.append(line)
        except (ValueError, OSError):
            pass
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    t_out = threading.Thread(target=_drain, args=(proc.stdout, out_chunks), daemon=True)
    t_err = threading.Thread(target=_drain, args=(proc.stderr, err_chunks), daemon=True)
    t_out.start()
    t_err.start()

    if input_text is not None and proc.stdin is not None:
        try:
            proc.stdin.write(input_text)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    start = time.monotonic()
    reason = ""
    while True:
        if proc.poll() is not None:
            break
        if cancel_event is not None and cancel_event.is_set():
            _terminate(proc)
            reason = "cancelled"
            break
        if time.monotonic() - start > timeout:
            _terminate(proc)
            reason = f"timed out after {timeout}s"
            break
        time.sleep(0.2)

    t_out.join(timeout=2)
    t_err.join(timeout=2)
    out = "".join(out_chunks)
    err = "".join(err_chunks)
    if reason:
        return -1, out, err or reason
    return proc.returncode, out, err


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


# A single DNS label: 1-63 chars, alnum + hyphen, no leading/trailing hyphen.
_HOST_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
# A plausible TLD: 2+ letters, or a punycode (IDN) label.
_HOST_TLD = re.compile(r"^(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9]{2,59})$")


def is_valid_host(host: str) -> bool:
    """True if ``host`` is a usable scan target: an IP, ``localhost``, or a
    fully-qualified domain (at least one dot and a real-looking TLD).

    This is what separates a genuine target like ``example.com`` from a typo
    like ``htt`` — the latter has no dot and no TLD, so it can never resolve.
    """
    h = (host or "").strip().rstrip(".")  # tolerate a trailing-dot FQDN
    if not h:
        return False
    # Bracketed IPv6 literal, e.g. "[::1]".
    if h.startswith("[") and "]" in h:
        h = h[1 : h.index("]")]
    if is_ip(h):
        return True
    if h.lower() == "localhost":
        return True
    if len(h) > 253:
        return False
    labels = h.split(".")
    if len(labels) < 2:
        return False  # single-label host (e.g. "htt") — not a domain
    if not all(_HOST_LABEL.match(label) for label in labels):
        return False
    return bool(_HOST_TLD.match(labels[-1]))


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
    if not is_valid_host(host):
        raise TargetError(
            f"'{host}' is not a valid domain, IP, or host "
            "(expected something like example.com or 1.2.3.4)"
        )

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
