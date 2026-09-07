"""Himalaya 1.2 subprocess wrapper. Never logs stdout that might hold bodies unless asked."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .security import himalaya_child_env, redact, require_himalaya_version, sanitize_folder, sanitize_message_id


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
            args.extend(query)
        raw = self._run(args)
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
                sanitize_message_id(message_id),
            ]
            self._run(args, timeout=120)
            try:
                return dest.read_bytes()
            except OSError as e:
                raise HimalayaError(f"export produced no message: {e}") from e

    def send_raw(self, rfc822: str) -> None:
        try:
            r = subprocess.run(
                [self.binary, "message", "send"],
                input=rfc822,
                capture_output=True,
                text=True,
                timeout=60,
                env=himalaya_child_env(),
            )
        except subprocess.TimeoutExpired as e:
            raise HimalayaError("send timed out") from e
        if r.returncode != 0:
            raise HimalayaError(redact((r.stderr or r.stdout or "send failed")[:400]))

    def folders(self) -> str:
        return self._run(["folder", "list"], timeout=20)
