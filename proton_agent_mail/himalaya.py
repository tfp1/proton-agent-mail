"""Himalaya 1.2 subprocess wrapper. Never logs stdout that might hold bodies unless asked.

Read paths only. This fork has no send path, and deliberately no wrapper for the
IMAP write verbs either -- `message delete`, `move`, `copy` and `flag add` are all
writes that need no SMTP, so "SMTP is blocked" would not have covered them.
See homelab#91.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .security import himalaya_child_env, redact, require_himalaya_version, sanitize_folder, sanitize_message_id


# Envelope listing is the slowest read: a sorted listing scales with folder
# size, and Sent already measures 17.5s against the default 35s.
LIST_TIMEOUT = int(os.environ.get("PROTON_AGENT_LIST_TIMEOUT", "60"))


class HimalayaError(RuntimeError):
    pass


class Himalaya:
    def __init__(self, binary: str | None = None, timeout: int = 35) -> None:
        self.binary = binary or os.environ.get("HIMALAYA_BIN") or shutil.which("himalaya") or "himalaya"
        self.timeout = timeout
        self.version = require_himalaya_version(self.binary)

    def _run(self, args: list[str], timeout: int | None = None) -> str:
        cmd = [self.binary, *args]
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
                env=himalaya_child_env(),
            )
        except subprocess.TimeoutExpired as e:
            raise HimalayaError("himalaya timed out") from e
        if r.returncode != 0:
            err = redact((r.stderr or r.stdout or "failed")[:400])
            raise HimalayaError(err)
        return r.stdout or ""

    def envelopes(self, n: int = 20, folder: str = "INBOX", query: list[str] | None = None) -> list[dict[str, Any]]:
        folder = sanitize_folder(folder)
        args = ["envelope", "list", "-s", str(n), "--output", "json", "--folder", folder]
        if query:
            # QUERY is positional and last, so "--" keeps a token that begins
            # with "-" from being read as a flag. Same reasoning as read().
            args.append("--")
            args.extend(query)
        raw = self._run(args, timeout=LIST_TIMEOUT)
        text = raw.strip()
        if not text.startswith("["):
            i = text.find("[")
            text = text[i:] if i >= 0 else "[]"
        data = json.loads(text)
        if not isinstance(data, list):
            raise HimalayaError("unexpected envelope payload")
        return data

    def read(self, message_id: str, folder: str = "INBOX") -> str:
        # Two separate hazards, both handled here:
        #  - envelope ids are per-folder, so a read that does not pass --folder
        #    resolves the id against INBOX no matter where it was listed from;
        #  - "--" so a value can never be parsed as an option, even if the
        #    allowlist is later loosened.
        args = [
            "message",
            "read",
            "--folder",
            sanitize_folder(folder),
            "--",
            sanitize_message_id(message_id),
        ]
        return self._run(args, timeout=45)

    def export_raw(self, message_id: str, folder: str = "INBOX") -> bytes:
        """Full raw RFC822 for one message.

        `message export --full` writes a .eml rather than printing to stdout,
        so it lands in a private temp dir that is removed before we return.
        """
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "message.eml"
            args = [
                "message",
                "export",
                "--full",
                "--folder",
                sanitize_folder(folder),
                "--destination",
                str(dest),
                "--",
                sanitize_message_id(message_id),
            ]
            self._run(args, timeout=120)
            try:
                return dest.read_bytes()
            except OSError as e:
                raise HimalayaError(f"export produced no message: {e}") from e

    def folders(self) -> str:
        return self._run(["folder", "list"], timeout=20)

    def folder_names(self) -> list[str]:
        """Folder names as a plain list.

        `folder list --output json` is a list of objects in himalaya 1.2, but
        the plain renderer is a table and the JSON shape is not part of any
        stability promise, so accept a bare list of strings too rather than
        turning a future field rename into a 502.
        """
        raw = self._run(["folder", "list", "--output", "json"], timeout=20).strip()
        if not raw.startswith("["):
            i = raw.find("[")
            raw = raw[i:] if i >= 0 else "[]"
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise HimalayaError(f"unexpected folder payload: {e}") from e
        if not isinstance(data, list):
            raise HimalayaError("unexpected folder payload")
        names = []
        for item in data:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict):
                name = item.get("name") or item.get("folder")
                if isinstance(name, str) and name:
                    names.append(name)
        return names
