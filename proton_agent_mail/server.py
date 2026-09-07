"""Minimal AgentMail-shaped HTTP API (stdlib only). Read-only fork -- see homelab#91."""

from __future__ import annotations

import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import attachments
from .himalaya import Himalaya, HimalayaError
from .security import (
    FolderDenied,
    assert_bridge_loopback,
    assert_folder_allowed,
    assert_config_private,
    assert_himalaya_bridge_hosts,
    assert_no_smtp_config,
    default_bind,
    default_folder,
    extract_bearer,
    folder_scope,
    load_token,
    redact,
    sanitize_since,
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


# An attachment is the one response that is not small JSON. Cap it so a large
# message cannot be used to exhaust the agent host's memory; do_POST already
# caps inbound bodies the same way.
MAX_ATTACHMENT_BYTES = int(
    os.environ.get("PROTON_AGENT_MAX_ATTACHMENT", str(25 * 1024 * 1024))
)


def _octets(
    handler: BaseHTTPRequestHandler, body: bytes, content_type: str, filename: str
) -> None:
    handler.send_response(200)
    # never echo the sender's content type; it steers the client's parser
    handler.send_header("Content-Type", "application/octet-stream")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
    handler.send_header("X-Attachment-Content-Type", content_type)
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


class AgentHandler(BaseHTTPRequestHandler):
    server_version = "proton-agent-mail/0.1"
    token = ""
    himalaya: Himalaya
    inbox_id = "default"
    email_addr = "agent@localhost"
    folders: tuple[str, ...] | None = None

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
                            {
                                "email": self.email_addr,
                                "inbox_id": self.inbox_id,
                                "provider": "proton-bridge",
                                # null means unrestricted; a list lets an agent
                                # discover its scope instead of probing for 403s
                                "folders": list(self.folders) if self.folders else None,
                            }
                        ]
                    },
                )
                return
            if path == f"/inboxes/{self.inbox_id}/folders":
                names = self.himalaya.folder_names()
                if self.folders is not None:
                    # a scoped consumer should not learn the names of folders
                    # it cannot read, so intersect rather than annotate
                    allowed = set(self.folders)
                    names = [n for n in names if n in allowed]
                _json(self, 200, {"count": len(names), "folders": names})
                return
            if path == f"/inboxes/{self.inbox_id}/messages":
                try:
                    requested = int((qs.get("limit") or ["20"])[0])
                except ValueError:
                    # do not reflect the caller's string back at them
                    raise RuntimeError("limit must be an integer") from None
                n = max(1, min(requested, 50))
                folder = (qs.get("folder") or [default_folder(self.folders)])[0]
                folder = assert_folder_allowed(folder, self.folders)
                raw_since = (qs.get("since") or [""])[0]
                since = sanitize_since(raw_since) if raw_since else None
                query = ["after", since] if since else []
                # Ordering is stated rather than inherited: a polling consumer
                # pages from the top, and himalaya's default order is not a
                # documented guarantee.
                query += ["order", "by", "date", "desc"]
                items = self.himalaya.envelopes(n=n, folder=folder, query=query)
                _json(
                    self,
                    200,
                    {
                        "count": len(items),
                        "limit": n,
                        # the cap used to apply silently; say so instead
                        "capped": requested > n,
                        "since": since,
                        "messages": items,
                    },
                )
                return
            prefix = f"/inboxes/{self.inbox_id}/messages/"
            rest = path[len(prefix):] if path.startswith(prefix) else ""
            # match on the remainder, not the whole path: an id of literally
            # "attachments" would otherwise route here with an empty id
            if "/attachments" in rest:
                mid, _, tail = rest.partition("/attachments")
                folder = (qs.get("folder") or [default_folder(self.folders)])[0]
                folder = assert_folder_allowed(folder, self.folders)
                raw = self.himalaya.export_raw(mid, folder=folder)
                if tail in ("", "/"):
                    items = attachments.listing(raw)
                    _json(self, 200, {"count": len(items), "attachments": items})
                    return
                try:
                    index = int(tail.lstrip("/"))
                except ValueError:
                    _json(self, 400, {"error": "attachment index must be an integer"})
                    return
                try:
                    body, ctype, name = attachments.payload(raw, index)
                except IndexError:
                    _json(self, 404, {"error": "no such attachment"})
                    return
                if len(body) > MAX_ATTACHMENT_BYTES:
                    _json(
                        self,
                        413,
                        {
                            "error": "attachment too large",
                            "size": len(body),
                            "limit": MAX_ATTACHMENT_BYTES,
                        },
                    )
                    return
                _octets(self, body, ctype, name)
                return
            if path.startswith(prefix):
                mid = path.rsplit("/", 1)[-1]
                folder = (qs.get("folder") or [default_folder(self.folders)])[0]
                folder = assert_folder_allowed(folder, self.folders)
                text = self.himalaya.read(mid, folder=folder)
                _json(self, 200, {"message_id": mid, "folder": folder, "text": text})
                return
            if path == f"/inboxes/{self.inbox_id}/threads":
                items = self.himalaya.envelopes(n=20, folder=default_folder(self.folders))
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
        except FolderDenied as e:
            _json(self, 403, {"error": str(e)})
            return
        except HimalayaError as e:
            _json(self, 502, {"error": str(e)})
            return
        except (ValueError, RuntimeError) as e:
            # A malformed parameter is the caller's fault, not the server's.
            # Both orderings matter: HimalayaError and FolderDenied are
            # RuntimeErrors, so they must be caught above this.
            _json(self, 400, {"error": redact(str(e))})
            return
        _json(self, 404, {"error": "not found"})

    # This fork is read-only. The refusal is explicit rather than "no route
    # matched" so that a mutating verb reads as a decision in the code, and so
    # that adding one back is a visible diff rather than a new branch in do_GET.
    def _refuse(self) -> None:
        _json(self, 405, {"error": "this inbox is read-only: no send, no delete, no move"})

    do_POST = _refuse       # noqa: N815 -- send lived here upstream
    do_PUT = _refuse        # noqa: N815
    do_PATCH = _refuse      # noqa: N815
    do_DELETE = _refuse     # noqa: N815


def serve(host: str | None = None, port: int | None = None) -> None:
    assert_bridge_loopback()
    cfg = Path.home() / ".config" / "himalaya" / "config.toml"
    assert_config_private(cfg)
    assert_himalaya_bridge_hosts(cfg)
    assert_no_smtp_config(cfg)
    token = load_token()
    him = Himalaya()
    host = host or default_bind()
    port = int(port or os.environ.get("PROTON_AGENT_PORT", "18765"))
    AgentHandler.token = token
    AgentHandler.himalaya = him
    AgentHandler.inbox_id = os.environ.get("PROTON_AGENT_INBOX", "default")
    AgentHandler.email_addr = os.environ.get(
        "PROTON_AGENT_EMAIL", os.environ.get("PROTON_AGENT_FROM", "agent@localhost")
    )
    AgentHandler.folders = folder_scope()
    httpd = ThreadingHTTPServer((host, port), AgentHandler)
    scope = ",".join(AgentHandler.folders) if AgentHandler.folders else "all folders"
    print(
        f"proton-agent-mail listening on {host}:{port} "
        f"inbox={AgentHandler.inbox_id} scope={scope}",
        flush=True,
    )
    httpd.serve_forever()
