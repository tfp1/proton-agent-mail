"""Hardening: token compare, version gate, bind policy, log redaction."""

from __future__ import annotations

import datetime
import hmac
import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path

MIN_HIMALAYA = (1, 2, 0)
SECRET_RE = re.compile(
    r"(auth\.raw\s*=\s*).+|"
    r"password['\"]?\s*[:=]\s*['\"]?[^'\"\s]+|"
    r"Bearer\s+[A-Za-z0-9._\-]+|"
    r"(sk_live|sk|pk|gho|ghp|github_pat)_[A-Za-z0-9_]+|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    re.I,
)

# Himalaya may only hop to Bridge on loopback.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
_HOST_LINE = re.compile(
    r"(?im)^(?:backend|message\.send\.backend)\.host\s*=\s*\"?([^\"\n#]+)\"?"
)


def redact(text: str) -> str:
    return SECRET_RE.sub("[redacted]", text or "")


def parse_himalaya_version(raw: str) -> tuple[int, int, int] | None:
    m = re.search(r"v?(\d+)\.(\d+)\.(\d+)", raw or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def require_himalaya_version(binary: str = "himalaya") -> tuple[int, int, int]:
    path = shutil.which(binary)
    if not path:
        raise RuntimeError("himalaya not found on PATH — install v1.2.0+")
    try:
        out = subprocess.check_output(
            [path, "--version"], text=True, timeout=8, stderr=subprocess.STDOUT
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise RuntimeError(f"himalaya --version failed: {e}") from e
    ver = parse_himalaya_version(out)
    if ver is None:
        raise RuntimeError(f"could not parse himalaya version from: {out[:80]!r}")
    if ver < MIN_HIMALAYA:
        raise RuntimeError(
            f"himalaya {ver[0]}.{ver[1]}.{ver[2]} is too old; "
            "Proton Bridge AUTH requires 1.2.0+ (1.1 hangs on PLAIN continuation)"
        )
    return ver


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_ok(provided: str | None, expected: str) -> bool:
    if not provided or not expected:
        return False
    a = provided.encode()
    b = expected.encode()
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)


def extract_bearer(header: str | None) -> str | None:
    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def default_bind() -> str:
    raw = os.environ.get("PROTON_AGENT_BIND", "127.0.0.1")
    if raw not in {"127.0.0.1", "::1"} and os.environ.get("PROTON_AGENT_ALLOW_LAN") != "1":
        raise RuntimeError(
            "refusing to bind non-loopback without PROTON_AGENT_ALLOW_LAN=1"
        )
    return raw


def load_token() -> str:
    env = os.environ.get("PROTON_AGENT_TOKEN", "").strip()
    if env:
        return env
    path = os.environ.get("PROTON_AGENT_TOKEN_FILE", "")
    if path:
        p = Path(path)
        if not p.is_file():
            raise RuntimeError("PROTON_AGENT_TOKEN_FILE not found")
        mode = p.stat().st_mode & 0o777
        if mode & 0o077:
            raise RuntimeError("token file must be mode 0600 or tighter (group/other bits set)")
        tok = p.read_text(encoding="utf-8").strip()
        if tok:
            return tok
    raise RuntimeError(
        "set PROTON_AGENT_TOKEN or PROTON_AGENT_TOKEN_FILE — refusing empty token"
    )


# Proton nests every label and user folder under "Labels/" or "Folders/", and
# at least one carries a timestamp, so "/" and ":" have to be admissible or 44
# of this mailbox's 52 folders are unreachable -- including Labels/Jobs, the one
# a scoped consumer needs. Neither character is dangerous here: the value is
# passed as an argv element to himalaya, never through a shell, and an IMAP
# folder is not a filesystem path. The leading-character anchor is what does the
# real work; it still rejects "-flag" and "../".
_FOLDER_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,63}$")
# first character is anchored the same way as _FOLDER_OK: a leading "-"
# would let the value reach himalaya's argument parser as a flag.
_ID_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def sanitize_folder(name: str) -> str:
    n = (name or "INBOX").strip() or "INBOX"
    if not _FOLDER_OK.match(n):
        raise RuntimeError("refusing unsafe folder name")
    return n


class FolderDenied(RuntimeError):
    """Requested folder is outside PROTON_AGENT_FOLDERS."""


def folder_scope() -> tuple[str, ...] | None:
    """Folders this agent may touch, in the order the operator wrote them.

    Unset (or empty) means every folder, which is the historical behaviour.
    Order is preserved so the first entry can serve as the default folder.
    """
    raw = os.environ.get("PROTON_AGENT_FOLDERS", "").strip()
    if not raw:
        return None
    names = tuple(dict.fromkeys(n.strip() for n in raw.split(",") if n.strip()))
    if not names:
        return None
    for n in names:
        # fail at startup on a malformed scope, not at the first request
        sanitize_folder(n)
    return names


def default_folder(scope: tuple[str, ...] | None) -> str:
    return "INBOX" if scope is None else scope[0]


def assert_folder_allowed(name: str, scope: tuple[str, ...] | None) -> str:
    """Shape-check the name, then check it against the scope.

    Matching is exact. IMAP folder names are case-sensitive apart from INBOX,
    so we do not fold case and risk admitting one the operator did not list.
    """
    n = sanitize_folder(name)
    if scope is not None and n not in scope:
        raise FolderDenied(f"folder {n!r} is outside this agent's scope")
    return n


_DATE_OK = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def sanitize_since(value: str) -> str:
    """Validate a ``since`` filter as a real calendar date, not just its shape.

    Two separate reasons this is strict. It reaches himalaya's argument parser
    as a positional query token, and it is the one request parameter a consumer
    is likely to build by string-formatting rather than by picking from a list.
    ``date.fromisoformat`` rejects 2026-02-31 and 2026-13-01, which the regex
    alone would accept.
    """
    v = (value or "").strip()
    if not _DATE_OK.match(v):
        raise RuntimeError("since must be YYYY-MM-DD")
    try:
        datetime.date.fromisoformat(v)
    except ValueError as e:
        raise RuntimeError(f"since is not a real date: {e}") from e
    return v


def sanitize_message_id(mid: str) -> str:
    if not mid or not _ID_OK.match(mid):
        raise RuntimeError("refusing unsafe message id")
    return mid


def himalaya_child_env() -> dict[str, str]:
    """Do not leak the agent bearer into the IMAP child."""
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "XDG_CONFIG_HOME", "HIMALAYA_CONFIG")
    out = {k: os.environ[k] for k in keep if os.environ.get(k)}
    out.setdefault("PATH", "/usr/bin:/bin")
    return out


def assert_bridge_loopback() -> None:
    """Refuse to start if Bridge IMAP/SMTP is on a public interface."""
    try:
        out = subprocess.check_output(
            ["ss", "-ltn"], text=True, timeout=5, stderr=subprocess.DEVNULL
        )
    except (OSError, subprocess.SubprocessError):
        return
    for port in ("1143", "1025"):
        for line in out.splitlines():
            if f":{port} " not in line and not line.rstrip().endswith(f":{port}"):
                continue
            if "127.0.0.1:" + port not in line and "[::1]:" + port not in line:
                raise RuntimeError(
                    f"Proton Bridge port {port} is not loopback-only — "
                    "fix Bridge to 127.0.0.1 before serving"
                )


def assert_config_private(path: Path) -> None:
    if not path.is_file():
        return
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise RuntimeError(f"{path} must be mode 0600 or tighter")


_SMTP_DECL = re.compile(r"(?im)^\s*message\.send\.backend|^\s*\[\s*accounts\.[^\]]+\.message\.send")


def assert_no_smtp_config(path: Path) -> None:
    """Refuse to serve if the Himalaya config declares a send backend at all.

    Not writing SMTP config is a property of setup(); this makes it a property of
    every start. Without it, a config edited by hand (or restored from a backup
    taken before this fork) would silently re-arm `himalaya message send` while
    every other layer still reported read-only.

    Does not print config contents -- they include auth.raw.
    """
    if not path.is_file():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise RuntimeError(f"cannot read himalaya config: {e}") from e
    if _SMTP_DECL.search(text):
        raise RuntimeError(
            f"{path} declares a send backend (message.send.*) — this build is "
            "read-only; remove the SMTP stanza before serving"
        )


def assert_himalaya_bridge_hosts(path: Path) -> None:
    """Refuse serve if Himalaya IMAP/SMTP host is not loopback.

    Does not print config contents (may include auth.raw).
    """
    if not path.is_file():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise RuntimeError(f"cannot read himalaya config: {e}") from e
    hosts = [m.group(1).strip() for m in _HOST_LINE.finditer(text)]
    if not hosts:
        # No host lines — leave to Himalaya; Bridge bind check still runs.
        return
    for host in hosts:
        h = host.strip().lower().strip('"').strip("'")
        if h not in _LOOPBACK_HOSTS:
            raise RuntimeError(
                "himalaya config points IMAP/SMTP off loopback — "
                "set backend.host and message.send.backend.host to 127.0.0.1"
            )
