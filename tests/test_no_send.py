"""The no-send / no-write contract of this fork.

Upstream ships a send route. homelab#91 requires that this build cannot send,
and — because `message delete`/`move`/`copy`/`flag add` are IMAP writes that
need no SMTP at all — that it cannot mutate the mailbox either. These tests
fail if any of that comes back.
"""

import ast
import pathlib
import tempfile
import unittest
from pathlib import Path

from proton_agent_mail import cli, server
from proton_agent_mail.himalaya import Himalaya
from proton_agent_mail.security import assert_no_smtp_config
from proton_agent_mail.setup import write_himalaya_config

PKG = pathlib.Path(__file__).resolve().parent.parent / "proton_agent_mail"

# IMAP write verbs. Blocking SMTP does not cover these.
FORBIDDEN_VERBS = ("delete", "move", "copy", "expunge", "flag")


class NoSendSurfaceTests(unittest.TestCase):
    def test_himalaya_wrapper_has_no_send(self):
        self.assertFalse(hasattr(Himalaya, "send_raw"))
        self.assertFalse([n for n in dir(Himalaya) if "send" in n.lower()])

    def test_server_has_no_rfc822_builder(self):
        self.assertFalse(hasattr(server, "_build_rfc822"))

    def test_cli_has_no_send_subcommand(self):
        src = (PKG / "cli.py").read_text()
        self.assertNotIn('add_parser("send")', src)
        self.assertNotIn("messages/send", src)
        self.assertFalse(hasattr(cli, "send"))


class MutatingVerbTests(unittest.TestCase):
    def test_mutating_http_methods_are_refused(self):
        for verb in ("do_POST", "do_PUT", "do_PATCH", "do_DELETE"):
            self.assertIs(
                getattr(server.AgentHandler, verb),
                server.AgentHandler._refuse,
                f"{verb} must route to the read-only refusal",
            )

    def test_no_imap_write_verb_reaches_a_subprocess(self):
        """Every string literal handed to himalaya, across the package.

        A wrapper for `message delete` would be a new argv literal, so this
        catches one being added even if nothing calls it yet.
        """
        for path in PKG.rglob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                if node.value in FORBIDDEN_VERBS:
                    self.fail(
                        f"{path.name}:{node.lineno} has the literal {node.value!r} — "
                        "an IMAP write verb must not reach himalaya"
                    )


class SmtpConfigTests(unittest.TestCase):
    def test_generated_config_declares_no_send_backend(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            real_home = Path.home
            try:
                Path.home = staticmethod(lambda: home)  # type: ignore[assignment]
                cfg = write_himalaya_config("a@b.com", "user", "pw")
            finally:
                Path.home = real_home  # type: ignore[assignment]
            body = cfg.read_text()
            self.assertIn("backend.type = \"imap\"", body)
            # a "#" line is prose, not a declaration -- compare the effective config
            live = "\n".join(
                ln for ln in body.splitlines() if not ln.lstrip().startswith("#")
            )
            self.assertNotIn("message.send", live)
            self.assertNotIn("smtp", live.lower())
            self.assertNotIn("1025", live)
            self.assertEqual(cfg.stat().st_mode & 0o777, 0o600)
            # the generated config must satisfy the startup gate
            assert_no_smtp_config(cfg)

    def test_serve_refuses_a_config_that_declares_smtp(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "config.toml"
            p.write_text(
                '[accounts.proton]\n'
                'backend.type = "imap"\n'
                'message.send.backend.type = "smtp"\n'
            )
            with self.assertRaises(RuntimeError) as ctx:
                assert_no_smtp_config(p)
            self.assertNotIn("auth.raw", str(ctx.exception))

    def test_clean_config_passes(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "config.toml"
            p.write_text('[accounts.proton]\nbackend.type = "imap"\n')
            assert_no_smtp_config(p)  # must not raise

    def test_missing_config_is_not_an_error(self):
        assert_no_smtp_config(Path("/nonexistent/config.toml"))


if __name__ == "__main__":
    unittest.main()
