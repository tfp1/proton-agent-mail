"""Envelope listing filters and the folder-listing route (homelab#91 step 2).

Covers the three gaps the runbook listed as blocking a scheduled consumer: no
`since` filter, no folder-listing route, and a limit that was capped silently.
"""

import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from proton_agent_mail import server
from proton_agent_mail.himalaya import Himalaya, HimalayaError
from proton_agent_mail.security import (
    FolderDenied,
    assert_folder_allowed,
    sanitize_folder,
    sanitize_since,
)


class SanitizeSinceTests(unittest.TestCase):
    def test_accepts_a_real_date(self):
        self.assertEqual(sanitize_since("2026-09-07"), "2026-09-07")
        self.assertEqual(sanitize_since("  2026-09-07 "), "2026-09-07")

    def test_rejects_wrong_shape(self):
        for bad in ("", "2026-9-7", "07/09/2026", "yesterday", "2026-09-07T00:00"):
            with self.assertRaises(RuntimeError, msg=bad):
                sanitize_since(bad)

    def test_rejects_dates_that_do_not_exist(self):
        # the shape regex accepts these; only the calendar check rejects them
        for bad in ("2026-02-31", "2026-13-01", "2026-00-10"):
            with self.assertRaises(RuntimeError, msg=bad):
                sanitize_since(bad)

    def test_rejects_a_flag_shaped_value(self):
        # it reaches himalaya's parser as a positional token
        with self.assertRaises(RuntimeError):
            sanitize_since("--config=/etc/passwd")


class _Recorder(Himalaya):
    """A Himalaya whose argv is captured instead of executed."""

    def __init__(self, stdout=""):
        self.binary = "himalaya"
        self.timeout = 5
        self.version = (1, 2, 0)
        self.calls = []
        self._stdout = stdout

    def _run(self, args, timeout=None):
        self.calls.append(list(args))
        return self._stdout


class EnvelopeArgvTests(unittest.TestCase):
    def test_query_is_separated_by_a_double_dash(self):
        him = _Recorder("[]")
        him.envelopes(n=5, folder="Archive", query=["after", "2026-09-01"])
        argv = him.calls[0]
        self.assertIn("--", argv)
        self.assertLess(argv.index("--"), argv.index("after"))
        # the folder still precedes the separator, as an option
        self.assertLess(argv.index("--folder"), argv.index("--"))

    def test_no_separator_when_there_is_no_query(self):
        him = _Recorder("[]")
        him.envelopes(n=5, folder="INBOX")
        self.assertNotIn("--", him.calls[0])


class FolderNameShapeTests(unittest.TestCase):
    """Proton nests labels under Labels/ and Folders/, so "/" must be allowed."""

    def test_proton_nested_folders_are_accepted(self):
        for name in ("Labels/Jobs", "Folders/Shopping", "Labels/Home-Bills-Loans",
                     "Folders/_2026-Q1 Job Search", "Labels/Unroll.me",
                     "Labels/2023-06-14T16:10 gmail migration", "All Mail", "INBOX"):
            self.assertEqual(sanitize_folder(name), name)

    def test_traversal_and_flags_are_still_refused(self):
        for bad in ("../../etc/passwd", "-flag", "/etc/passwd", ".hidden",
                    "a;rm -rf /", "a&b", "a$(id)", "a\nb", "a|b", '"a"'):
            with self.assertRaises(RuntimeError, msg=bad):
                sanitize_folder(bad)

    def test_scope_matching_still_works_on_a_nested_name(self):
        scope = ("Labels/Jobs",)
        self.assertEqual(assert_folder_allowed("Labels/Jobs", scope), "Labels/Jobs")
        with self.assertRaises(FolderDenied):
            assert_folder_allowed("Labels/Home", scope)


class FolderNamesTests(unittest.TestCase):
    def test_parses_objects(self):
        him = _Recorder(json.dumps([{"name": "INBOX"}, {"name": "Archive"}]))
        self.assertEqual(him.folder_names(), ["INBOX", "Archive"])

    def test_parses_bare_strings(self):
        him = _Recorder(json.dumps(["INBOX", "Archive"]))
        self.assertEqual(him.folder_names(), ["INBOX", "Archive"])

    def test_skips_entries_with_no_name_rather_than_failing(self):
        him = _Recorder(json.dumps([{"desc": "no name"}, {"name": "Archive"}, 7]))
        self.assertEqual(him.folder_names(), ["Archive"])

    def test_tolerates_a_preamble_before_the_json(self):
        him = _Recorder('warning: dbus-launch not found\n["INBOX"]')
        self.assertEqual(him.folder_names(), ["INBOX"])

    def test_non_json_is_a_himalaya_error_not_a_crash(self):
        him = _Recorder("[not json")
        with self.assertRaises(HimalayaError):
            him.folder_names()


class _FakeHimalaya(_Recorder):
    def __init__(self, count=50, folders=("INBOX", "Archive", "Jobs")):
        super().__init__()
        self._count = count
        self._folders = list(folders)
        self.last_query = None

    def envelopes(self, n=20, folder="INBOX", query=None):
        self.last_query = query
        return [{"id": str(i), "subject": f"s{i}"} for i in range(min(n, self._count))]

    def folder_names(self):
        return list(self._folders)


class RouteTests(unittest.TestCase):
    """Drive the real handler over a loopback socket with a fake backend."""

    def setUp(self):
        self.him = _FakeHimalaya()
        server.AgentHandler.token = "t0ken"
        server.AgentHandler.himalaya = self.him
        server.AgentHandler.inbox_id = "default"
        server.AgentHandler.folders = None
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.AgentHandler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        server.AgentHandler.folders = None

    def get(self, path):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            headers={"Authorization": "Bearer t0ken"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_limit_over_the_cap_reports_capped(self):
        code, body = self.get("/inboxes/default/messages?limit=200")
        self.assertEqual(code, 200)
        self.assertEqual(body["limit"], 50)
        self.assertTrue(body["capped"])
        self.assertEqual(body["count"], 50)

    def test_limit_within_the_cap_is_not_capped(self):
        code, body = self.get("/inboxes/default/messages?limit=10")
        self.assertEqual(code, 200)
        self.assertEqual(body["limit"], 10)
        self.assertFalse(body["capped"])

    def test_since_reaches_the_backend_query(self):
        code, body = self.get("/inboxes/default/messages?since=2026-09-01")
        self.assertEqual(code, 200)
        self.assertEqual(body["since"], "2026-09-01")
        self.assertEqual(self.him.last_query, ["after", "2026-09-01"])

    def test_no_sort_unless_asked(self):
        # sorting a large folder times out, so the default must stay unsorted
        self.get("/inboxes/default/messages")
        self.assertEqual(self.him.last_query, [])

    def test_order_is_opt_in(self):
        code, body = self.get("/inboxes/default/messages?order=date_desc")
        self.assertEqual(code, 200)
        self.assertEqual(body["order"], "date_desc")
        self.assertEqual(self.him.last_query, ["order", "by", "date", "desc"])

    def test_order_ascending(self):
        self.get("/inboxes/default/messages?order=date_asc")
        self.assertEqual(self.him.last_query, ["order", "by", "date", "asc"])

    def test_since_and_order_compose(self):
        self.get("/inboxes/default/messages?since=2026-09-01&order=date_desc")
        self.assertEqual(self.him.last_query,
                         ["after", "2026-09-01", "order", "by", "date", "desc"])

    def test_a_bad_order_is_a_400(self):
        # percent-encoded "; rm -rf /" -- it reaches himalaya's query parser as
        # a positional token, so only the allowlist keeps it out
        code, body = self.get("/inboxes/default/messages?order=%3B%20rm%20-rf%20%2F")
        self.assertEqual(code, 400)
        self.assertIn("order", body["error"])
        self.assertIsNone(self.him.last_query)

    def test_a_bad_since_is_a_400_not_a_500(self):
        code, body = self.get("/inboxes/default/messages?since=2026-02-31")
        self.assertEqual(code, 400)
        self.assertIn("since", body["error"])

    def test_a_non_numeric_limit_is_a_400_not_a_500(self):
        code, _ = self.get("/inboxes/default/messages?limit=abc")
        self.assertEqual(code, 400)

    def test_an_unsafe_folder_is_a_400_not_a_500(self):
        code, _ = self.get("/inboxes/default/messages?folder=../../etc")
        self.assertEqual(code, 400)

    def test_folders_route_lists_folders(self):
        code, body = self.get("/inboxes/default/folders")
        self.assertEqual(code, 200)
        self.assertEqual(body["folders"], ["INBOX", "Archive", "Jobs"])
        self.assertEqual(body["count"], 3)

    def test_folders_route_hides_out_of_scope_names(self):
        server.AgentHandler.folders = ("Jobs",)
        code, body = self.get("/inboxes/default/folders")
        self.assertEqual(code, 200)
        self.assertEqual(body["folders"], ["Jobs"])

    def test_folders_route_needs_auth(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/inboxes/default/folders")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 401)


if __name__ == "__main__":
    unittest.main()
