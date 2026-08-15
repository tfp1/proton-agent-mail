import unittest

from pathlib import Path
import tempfile

from proton_agent_mail.security import (
    MIN_HIMALAYA,
    parse_himalaya_version,
    redact,
    token_ok,
    extract_bearer,
    default_bind,
    new_token,
    sanitize_folder,
    sanitize_message_id,
    himalaya_child_env,
    assert_himalaya_bridge_hosts,
)


class SecurityTests(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(parse_himalaya_version("himalaya v1.2.0 +imap"), (1, 2, 0))
        self.assertLess(parse_himalaya_version("v1.1.0"), MIN_HIMALAYA)

    def test_token_compare(self):
        t = new_token()
        self.assertTrue(token_ok(t, t))
        self.assertFalse(token_ok(t[:-1] + "x", t))
        self.assertFalse(token_ok("", t))
        self.assertFalse(token_ok(None, t))

    def test_bearer(self):
        self.assertEqual(extract_bearer("Bearer abc"), "abc")
        self.assertIsNone(extract_bearer("Basic abc"))

    def test_redact(self):
        s = redact("Authorization: Bearer supersecretvalue")
        self.assertNotIn("supersecretvalue", s)

    def test_sanitize(self):
        self.assertEqual(sanitize_folder("INBOX"), "INBOX")
        with self.assertRaises(RuntimeError):
            sanitize_folder("../../etc/passwd")
        with self.assertRaises(RuntimeError):
            sanitize_message_id("; rm -rf /")

    def test_child_env_strips_token(self):
        import os

        os.environ["PROTON_AGENT_TOKEN"] = "should-not-leak"
        env = himalaya_child_env()
        self.assertNotIn("PROTON_AGENT_TOKEN", env)

    def test_bind_loopback(self):
        import os

        os.environ.pop("PROTON_AGENT_ALLOW_LAN", None)
        os.environ["PROTON_AGENT_BIND"] = "127.0.0.1"
        self.assertEqual(default_bind(), "127.0.0.1")
        os.environ["PROTON_AGENT_BIND"] = "0.0.0.0"
        with self.assertRaises(RuntimeError):
            default_bind()

    def test_himalaya_hosts_loopback_only(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "config.toml"
            p.write_text(
                'backend.host = "127.0.0.1"\n'
                'message.send.backend.host = "localhost"\n',
                encoding="utf-8",
            )
            assert_himalaya_bridge_hosts(p)
            p.write_text(
                'backend.host = "10.0.0.5"\n'
                'message.send.backend.host = "127.0.0.1"\n',
                encoding="utf-8",
            )
            with self.assertRaises(RuntimeError):
                assert_himalaya_bridge_hosts(p)


if __name__ == "__main__":
    unittest.main()
