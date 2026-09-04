"""Autonomous setup: agent installs everything; human only runs Bridge `login`."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

from .security import new_token, redact, require_himalaya_version

HIMALAYA_URL = (
    "https://github.com/pimalaya/himalaya/releases/download/"
    "v1.2.0/himalaya.x86_64-linux.tgz"
)
# sha256 of the tarball at HIMALAYA_URL. Regenerate when bumping the version:
#   curl -sSL "$HIMALAYA_URL" | sha256sum
HIMALAYA_SHA256 = "e04e6382e3e664ef34b01afa1a2216113194a2975d2859727647b22d9b36d4e4"
INFO_USER = re.compile(r"(?:Username|username|IMAP user)\s*[:=]\s*(\S+)", re.I)
INFO_PASS = re.compile(r"(?:Password|password|IMAP password)\s*[:=]\s*(\S+)", re.I)
INFO_EMAIL = re.compile(r"([\w.+-]+@[\w.-]+)", re.I)


def verify_sha256(path: Path, expected: str) -> None:
    """Refuse an archive whose digest does not match the pin."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    got = h.hexdigest()
    if not hmac.compare_digest(got, expected):
        raise RuntimeError(
            f"himalaya archive sha256 mismatch: expected {expected}, got {got}"
        )


def port_up(port: int, host: str = "127.0.0.1") -> bool:
    s = socket.socket()
    s.settimeout(0.4)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def parse_info(blob: str) -> dict[str, str]:
    user_m = INFO_USER.search(blob)
    pass_m = INFO_PASS.search(blob)
    emails = INFO_EMAIL.findall(blob)
    user = user_m.group(1) if user_m else ""
    pw = pass_m.group(1) if pass_m else ""
    email = emails[0] if emails else user
    return {"username": user, "password": pw, "email": email}


def which_bridge() -> str | None:
    for name in ("protonmail-bridge", "proton-bridge"):
        p = shutil.which(name)
        if p:
            return p
    p = Path("/usr/bin/protonmail-bridge")
    return str(p) if p.is_file() else None


def ensure_himalaya(dest_dir: Path | None = None) -> str:
    dest_dir = dest_dir or Path.home() / ".local" / "bin"
    dest_dir.mkdir(parents=True, exist_ok=True)
    existing = shutil.which("himalaya")
    if existing:
        try:
            require_himalaya_version(existing)
            return existing
        except RuntimeError:
            pass
    dest = dest_dir / "himalaya"
    print("installing Himalaya v1.2.0 to", dest, flush=True)
    with tempfile.TemporaryDirectory() as td:
        tgz = Path(td) / "himalaya.tgz"
        urllib.request.urlretrieve(HIMALAYA_URL, tgz)
        verify_sha256(tgz, HIMALAYA_SHA256)
        with tarfile.open(tgz) as tf:
            tf.extractall(td, filter="data")
        bin_src = next(Path(td).rglob("himalaya"))
        shutil.copy2(bin_src, dest)
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR)
    require_himalaya_version(str(dest))
    return str(dest)


def bridge_cli(bridge: str, command: str, timeout: int = 20) -> str:
    """One-shot CLI command. Never print the result (may contain IMAP password)."""
    proc = subprocess.run(
        [bridge, "-c"],
        input=f"{command}\nexit\n",
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return (proc.stdout or "") + "\n" + (proc.stderr or "")


def write_himalaya_config(email: str, username: str, password: str) -> Path:
    cfg = Path.home() / ".config" / "himalaya" / "config.toml"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    safe_pw = password.replace("\\", "\\\\").replace('"', '\\"')
    safe_user = username.replace('"', "")
    safe_email = email.replace('"', "")
    body = f"""[accounts.proton]
email = "{safe_email}"
display-name = "Proton Agent"
default = true

backend.type = "imap"
backend.host = "127.0.0.1"
backend.port = 1143
backend.encryption.type = "none"
backend.login = "{safe_user}"
backend.auth.type = "password"
backend.auth.raw = "{safe_pw}"

message.send.backend.type = "smtp"
message.send.backend.host = "127.0.0.1"
message.send.backend.port = 1025
message.send.backend.encryption.type = "none"
message.send.backend.login = "{safe_user}"
message.send.backend.auth.type = "password"
message.send.backend.auth.raw = "{safe_pw}"

folder.aliases.inbox = "INBOX"
folder.aliases.sent = "Sent"
"""
    cfg.write_text(body, encoding="utf-8")
    cfg.chmod(0o600)
    return cfg


def write_token_file() -> Path:
    p = Path.home() / ".config" / "proton-agent-mail.token"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(new_token() + "\n", encoding="utf-8")
    p.chmod(0o600)
    return p


def start_bridge_noninteractive(bridge: str) -> None:
    if port_up(1143) and port_up(1025):
        return
    subprocess.Popen(
        [bridge, "--noninteractive"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def wait_for_login(bridge: str, timeout: int = 900, every: int = 4) -> dict[str, str]:
    """Poll until Bridge has an account. Human must `login` in another terminal."""
    print(
        "WAITING_FOR_LOGIN: in another terminal run:\n"
        f"  {bridge} -c\n"
        "  login\n"
        "Sign in there (2FA if asked). I will continue when Bridge accepts it.\n"
        "Do not paste your Proton password into this chat.",
        flush=True,
    )
    deadline = time.time() + timeout
    while time.time() < deadline:
        if port_up(1143) and port_up(1025):
            try:
                raw = bridge_cli(bridge, "info")
            except (subprocess.TimeoutExpired, OSError):
                time.sleep(every)
                continue
            parsed = parse_info(raw)
            if parsed["username"] and parsed["password"]:
                print("LOGIN_ACCEPTED", flush=True)
                return parsed
        time.sleep(every)
    raise RuntimeError("timed out waiting for Bridge login")


def setup(*, watch: bool = True) -> None:
    him = ensure_himalaya()
    print("himalaya_ok", him, flush=True)
    bridge = which_bridge()
    if not bridge:
        print(
            "NEED_BRIDGE: install Proton Mail Bridge from https://proton.me/mail/bridge "
            "then re-run: proton-agent-mail setup",
            flush=True,
        )
        sys.exit(2)
    start_bridge_noninteractive(bridge)
    creds = wait_for_login(bridge) if watch else parse_info(bridge_cli(bridge, "info"))
    if not creds.get("password"):
        raise RuntimeError("Bridge info had no IMAP password yet — finish login")
    cfg = write_himalaya_config(creds["email"] or creds["username"], creds["username"], creds["password"])
    tok = write_token_file()
    print(f"CONFIGURED himalaya={cfg} token_file={tok} (secrets not printed)", flush=True)
    print("NEXT: PROTON_AGENT_TOKEN_FILE=%s PROTON_AGENT_FROM='%s' proton-agent-mail serve" % (tok, creds["email"]), flush=True)
