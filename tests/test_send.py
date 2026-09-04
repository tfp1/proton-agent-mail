import unittest

from proton_agent_mail.server import _build_rfc822


class SendHeaderTests(unittest.TestCase):
    """A caller that reaches /messages/send already holds the bearer token, so
    these guard the case the threat model cares about: an agent that has been
    prompt-injected smuggling extra headers through `to` or `subject`."""

    def test_rejects_crlf_in_subject(self):
        with self.assertRaises(ValueError):
            _build_rfc822(
                from_addr="agent@localhost",
                to="a@b.com",
                subject="Hi\r\nBcc: evil@example.com",
                text="body",
                message_id="<id@localhost>",
            )

    def test_rejects_newline_in_to(self):
        with self.assertRaises(ValueError):
            _build_rfc822(
                from_addr="agent@localhost",
                to="a@b.com\nBcc: evil@example.com",
                subject="Hi",
                text="body",
                message_id="<id@localhost>",
            )

    def test_clean_message_keeps_its_headers(self):
        raw = _build_rfc822(
            from_addr="agent@localhost",
            to="a@b.com",
            subject="Hi",
            text="body",
            message_id="<id@localhost>",
        )
        self.assertIn("To: a@b.com", raw)
        self.assertIn("Subject: Hi", raw)
        self.assertIn("body", raw)
        self.assertNotIn("Bcc", raw)


if __name__ == "__main__":
    unittest.main()
