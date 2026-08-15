"""Minimal AgentMail-shaped HTTP API (stdlib only)."""

from __future__ import annotations

import email.utils
import json
import os
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .himalaya import Himalaya, HimalayaError
from .security import (
    assert_bridge_loopback,
    assert_config_private,
    assert_himalaya_bridge_hosts,
    default_bind,
    extract_bearer,
    load_token,
    redact,
    token_ok,
)


def _json(handler: BaseHTTPRequestHandler, code: int, payload: Any) -> None:
    body = json.dumps(payload).encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


class AgentHandler(BaseHTTPRequestHandler):
    server_version = "proton-agent-mail/0.1"
    token = ""
    himalaya: Himalaya
    inbox_id = "default"
    from_addr = "agent@localhost"

    def log_message(self, fmt: str, *args: Any) -> None:
        msg = redact(fmt % args)
        sys_stderr = __import__("sys").stderr
        print(f"{self.address_string()} {msg}", file=sys_stderr)

    def _auth(self) -> bool:
        got = extract_bearer(self.headers.get("Authorization"))
        if token_ok(got, self.token):
            return True
        _json(self, 401, {"error": "unauthorized"})
        return False

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/health":
            _json(
                self,
                200,
                {
                    "ok": True,
                    "himalaya": ".".join(str(x) for x in self.himalaya.version),
                    "inbox": self.inbox_id,
                },
            )
            return
        if not self._auth():
            return
        qs = parse_qs(urlparse(self.path).query)
        try:
            if path in {"/inboxes", f"/inboxes/{self.inbox_id}"}:
                _json(
                    self,
                    200,
                    {
                        "inboxes": [
                            {"email": self.from_addr, "inbox_id": self.inbox_id, "provider": "proton-bridge"}
                        ]
                    },
                )
                return
            if path == f"/inboxes/{self.inbox_id}/messages":
                n = int((qs.get("limit") or ["20"])[0])
                n = max(1, min(n, 50))
                folder = (qs.get("folder") or ["INBOX"])[0]
                items = self.himalaya.envelopes(n=n, folder=folder)
                _json(self, 200, {"count": len(items), "messages": items})
                return
            if path.startswith(f"/inboxes/{self.inbox_id}/messages/"):
                mid = path.rsplit("/", 1)[-1]
                text = self.himalaya.read(mid)
                _json(self, 200, {"message_id": mid, "text": text})
                return
            if path == f"/inboxes/{self.inbox_id}/threads":
                items = self.himalaya.envelopes(n=20)
                _json(
                    self,
                    200,
                    {
                        "count": len(items),
                        "threads": [
                            {
                                "thread_id": i.get("id"),
                                "subject": i.get("subject"),
                                "from": i.get("from"),
                            }
                            for i in items
                        ],
                    },
                )
                return
        except HimalayaError as e:
            _json(self, 502, {"error": str(e)})
            return
        _json(self, 404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._auth():
            return
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        if length > 200_000:
            _json(self, 413, {"error": "payload too large"})
            return
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            _json(self, 400, {"error": "invalid json"})
            return
        if path != f"/inboxes/{self.inbox_id}/messages/send":
            _json(self, 404, {"error": "not found"})
            return
        to = data.get("to")
        if isinstance(to, list):
            to = to[0] if to else ""
        subject = data.get("subject") or ""
        text = data.get("text") or data.get("body") or ""
        if not to or not subject:
            _json(self, 400, {"error": "to and subject required"})
            return
        mid = f"<pam-{int(time.time())}-{os.getpid()}@localhost>"
        rfc = (
            f"From: {self.from_addr}\r\n"
            f"To: {to}\r\n"
            f"Subject: {subject}\r\n"
            f"Date: {email.utils.formatdate(localtime=True)}\r\n"
            f"Message-ID: {mid}\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            f"{text}\n"
        )
        try:
            self.himalaya.send_raw(rfc)
        except HimalayaError as e:
            _json(self, 502, {"error": str(e)})
            return
        _json(self, 200, {"ok": True, "message_id": mid})


def serve(host: str | None = None, port: int | None = None) -> None:
    assert_bridge_loopback()
    cfg = Path.home() / ".config" / "himalaya" / "config.toml"
    assert_config_private(cfg)
    assert_himalaya_bridge_hosts(cfg)
    token = load_token()
    him = Himalaya()
    host = host or default_bind()
    port = int(port or os.environ.get("PROTON_AGENT_PORT", "18765"))
    AgentHandler.token = token
    AgentHandler.himalaya = him
    AgentHandler.inbox_id = os.environ.get("PROTON_AGENT_INBOX", "default")
    AgentHandler.from_addr = os.environ.get("PROTON_AGENT_FROM", "agent@localhost")
    httpd = ThreadingHTTPServer((host, port), AgentHandler)
    print(f"proton-agent-mail listening on {host}:{port} inbox={AgentHandler.inbox_id}", flush=True)
    httpd.serve_forever()
