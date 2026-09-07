import os
import unittest

from proton_agent_mail.himalaya import Himalaya
from proton_agent_mail.security import (
    FolderDenied,
    assert_folder_allowed,
    default_folder,
    folder_scope,
)


class FolderScopeTests(unittest.TestCase):
    def setUp(self):
        os.environ.pop("PROTON_AGENT_FOLDERS", None)

    tearDown = setUp

    def test_unset_means_unrestricted(self):
        self.assertIsNone(folder_scope())
        self.assertEqual(default_folder(None), "INBOX")
        # unrestricted still shape-checks
        self.assertEqual(assert_folder_allowed("Archive", None), "Archive")
        with self.assertRaises(RuntimeError):
            assert_folder_allowed("../../etc/passwd", None)

    def test_scope_preserves_order_and_dedupes(self):
        os.environ["PROTON_AGENT_FOLDERS"] = " Jobs , Receipts ,Jobs "
        self.assertEqual(folder_scope(), ("Jobs", "Receipts"))

    def test_first_entry_is_the_default_folder(self):
        os.environ["PROTON_AGENT_FOLDERS"] = "Jobs,Receipts"
        self.assertEqual(default_folder(folder_scope()), "Jobs")

    def test_out_of_scope_is_denied(self):
        scope = ("Jobs",)
        self.assertEqual(assert_folder_allowed("Jobs", scope), "Jobs")
        with self.assertRaises(FolderDenied):
            assert_folder_allowed("INBOX", scope)
        with self.assertRaises(FolderDenied):
            assert_folder_allowed("Archive", scope)

    def test_match_is_case_sensitive(self):
        # IMAP folder names are case-sensitive apart from INBOX; folding case
        # would admit a folder the operator never listed
        with self.assertRaises(FolderDenied):
            assert_folder_allowed("jobs", ("Jobs",))

    def test_malformed_scope_fails_at_startup(self):
        os.environ["PROTON_AGENT_FOLDERS"] = "Jobs,../etc"
        with self.assertRaises(RuntimeError):
            folder_scope()


class ReadFolderTests(unittest.TestCase):
    """Envelope ids are per-folder. Without --folder, himalaya resolves the id
    against INBOX regardless of which folder it was listed from."""

    def _stub(self):
        him = Himalaya.__new__(Himalaya)
        him.binary = "himalaya"
        him.timeout = 35
        him.version = (1, 2, 0)
        seen = []
        him._run = lambda args, timeout=None: seen.append(args) or ""
        return him, seen

    def test_read_passes_folder(self):
        him, seen = self._stub()
        him.read("42", folder="Jobs")
        self.assertIn("--folder", seen[0])
        self.assertEqual(seen[0][seen[0].index("--folder") + 1], "Jobs")

    def test_read_defaults_to_inbox(self):
        him, seen = self._stub()
        him.read("42")
        self.assertEqual(seen[0][seen[0].index("--folder") + 1], "INBOX")

    def test_read_rejects_unsafe_folder(self):
        him, _ = self._stub()
        with self.assertRaises(RuntimeError):
            him.read("42", folder="../../etc")


if __name__ == "__main__":
    unittest.main()
