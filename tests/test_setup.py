import unittest

from proton_agent_mail.setup import parse_info, port_up


class SetupParseTests(unittest.TestCase):
    def test_parse_info_table(self):
        blob = """
        Configuration for account user@example.com
        Username: user@example.com
        Password: xK9fakeBridgeSecret
        IMAP: 127.0.0.1:1143
        SMTP: 127.0.0.1:1025
        """
        p = parse_info(blob)
        self.assertEqual(p["username"], "user@example.com")
        self.assertEqual(p["password"], "xK9fakeBridgeSecret")
        self.assertIn("@", p["email"])

    def test_port_loopback_closed_high(self):
        self.assertFalse(port_up(1))


if __name__ == "__main__":
    unittest.main()


class ArchivePinTests(unittest.TestCase):
    def test_verify_sha256_accepts_and_rejects(self):
        import hashlib
        import tempfile
        from pathlib import Path

        from proton_agent_mail.setup import verify_sha256

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "blob"
            p.write_bytes(b"himalaya")
            good = hashlib.sha256(b"himalaya").hexdigest()
            verify_sha256(p, good)
            with self.assertRaises(RuntimeError):
                verify_sha256(p, "0" * 64)
