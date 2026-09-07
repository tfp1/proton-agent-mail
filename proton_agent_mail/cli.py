"""CLI: proton-agent-mail {serve,health,list,read,attachments,token}

Read-only fork -- there is no send subcommand. See homelab#91."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import quote

from . import __version__
from .security import default_bind, load_token, new_token


def _url() -> str:
    host = os.environ.get("PROTON_AGENT_BIND", "127.0.0.1")
    port = os.environ.get("PROTON_AGENT_PORT", "18765")
    inbox = os.environ.get("PROTON_AGENT_INBOX", "default")
    return f"http://{host}:{port}", inbox


def _req(method: str, path: str, body: dict | None = None, auth: bool = True) -> dict:
    base, _ = _url()
    data = None if body is None else json.dumps(body).encode()
    headers = {"Content-Type": "application/json", "User-Agent": f"proton-agent-mail/{__version__}"}
    if auth:
        headers["Authorization"] = f"Bearer {load_token()}"
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        err = e.read().decode()[:400]
        raise SystemExit(f"HTTP {e.code}: {err}") from e


def main() -> None:
    p = argparse.ArgumentParser(prog="proton-agent-mail")
    p.add_argument("--version", action="version", version=f"proton-agent-mail {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("serve")
    sub.add_parser("health")
    sub.add_parser("token")
    lst = sub.add_parser("list")
    lst.add_argument("--limit", type=int, default=15)
    lst.add_argument("--folder", default="")
    rd = sub.add_parser("read")
    rd.add_argument("id")
    rd.add_argument("--folder", default="")
    att = sub.add_parser("attachments")
    att.add_argument("id")
    att.add_argument("--folder", default="")
    sub.add_parser("setup")
    args = p.parse_args()

    if args.cmd == "token":
        print(new_token())
        return
    if args.cmd == "setup":
        from .setup import setup

        setup(watch=True)
        return
    if args.cmd == "serve":
        from .server import serve

        serve()
        return
    if args.cmd == "health":
        print(json.dumps(_req("GET", "/health", auth=False), indent=2))
        return
    _, inbox = _url()
    if args.cmd == "list":
        q = f"&folder={quote(args.folder)}" if args.folder else ""
        print(
            json.dumps(_req("GET", f"/inboxes/{inbox}/messages?limit={args.limit}{q}"), indent=2)
        )
        return
    if args.cmd == "read":
        q = f"?folder={quote(args.folder)}" if args.folder else ""
        print(json.dumps(_req("GET", f"/inboxes/{inbox}/messages/{args.id}{q}"), indent=2))
        return
    if args.cmd == "attachments":
        q = f"?folder={quote(args.folder)}" if args.folder else ""
        print(
            json.dumps(
                _req("GET", f"/inboxes/{inbox}/messages/{args.id}/attachments{q}"), indent=2
            )
        )
        return


if __name__ == "__main__":
    main()
