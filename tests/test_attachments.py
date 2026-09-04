import unittest
from email.message import EmailMessage

from proton_agent_mail.attachments import listing, payload, safe_filename


def _msg_with_attachments() -> bytes:
    m = EmailMessage()
    m["From"] = "broker@example.com"
    m["To"] = "me@example.com"
    m["Subject"] = "Renewal"
    m.set_content("See attached.")
    m.add_attachment(
        b"%PDF-1.4 quote", maintype="application", subtype="pdf", filename="quote.pdf"
    )
    m.add_attachment(
        b"col1,col2\n", maintype="text", subtype="csv", filename="schedule.csv"
    )
    return m.as_bytes()


class ListingTests(unittest.TestCase):
    def test_lists_attachments_not_the_body(self):
        items = listing(_msg_with_attachments())
        self.assertEqual([i["filename"] for i in items], ["quote.pdf", "schedule.csv"])
        self.assertEqual(items[0]["content_type"], "application/pdf")
        self.assertEqual(items[0]["size"], len(b"%PDF-1.4 quote"))

    def test_message_without_attachments_is_empty(self):
        m = EmailMessage()
        m["Subject"] = "no files"
        m.set_content("hi")
        self.assertEqual(listing(m.as_bytes()), [])

    def test_inline_part_with_filename_counts(self):
        # brokers and insurers routinely send documents as inline, not attachment
        m = EmailMessage()
        m["Subject"] = "inline"
        m.set_content("body")
        m.add_attachment(b"data", maintype="application", subtype="pdf",
                         filename="policy.pdf", disposition="inline")
        self.assertEqual([i["filename"] for i in listing(m.as_bytes())], ["policy.pdf"])


class PayloadTests(unittest.TestCase):
    def test_returns_decoded_bytes(self):
        body, ctype, name = payload(_msg_with_attachments(), 0)
        self.assertEqual(body, b"%PDF-1.4 quote")
        self.assertEqual(ctype, "application/pdf")
        self.assertEqual(name, "quote.pdf")

    def test_out_of_range(self):
        with self.assertRaises(IndexError):
            payload(_msg_with_attachments(), 9)


class SafeFilenameTests(unittest.TestCase):
    """The sender picks this string; it reaches a Content-Disposition header."""

    def test_strips_header_injection(self):
        self.assertNotIn("\r", safe_filename('a"\r\nSet-Cookie: x=1', 0))
        self.assertNotIn("\n", safe_filename('a"\r\nSet-Cookie: x=1', 0))
        self.assertNotIn('"', safe_filename('a"\r\nSet-Cookie: x=1', 0))

    def test_strips_path_separators(self):
        self.assertNotIn("/", safe_filename("../../etc/passwd", 0))

    def test_falls_back_when_empty_or_missing(self):
        self.assertEqual(safe_filename(None, 3), "attachment-3")
        self.assertEqual(safe_filename("///", 2), "attachment-2")


if __name__ == "__main__":
    unittest.main()
