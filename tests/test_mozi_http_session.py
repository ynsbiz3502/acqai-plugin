"""The HTTP transport's session: the cookies the browser login saved, read
from storage-state.json, kept fresh from Set-Cookie replies, and the fallback
to the browser when they do not serve. Nothing here reaches ACQ AI: the
request is replaced, and the browser send is a fake."""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "acqai" / "scripts"
_SCRATCH = tempfile.TemporaryDirectory()
os.environ.setdefault("ACQAI_STATE_DIR", _SCRATCH.name)
sys.path.insert(0, str(SCRIPTS))

import acqai  # noqa: E402
import mozilib  # noqa: E402

AEGIS = "__Secure-aegis-external.session_token"
ROUTE = {
    "url": "https://portal.acquisition.com/api/sandbar/chat-stream",
    "method": "POST",
    "message_slot": "messages[-1].content",
    "stream": True,
    "body_template": {"messages": [{"id": "m1", "role": "user", "content": "x"}],
                      "toolContext": {"chatId": "c0"}},
}


def cookie(name: str, value: str = "v", *, domain: str = ".acquisition.com",
           expires: float | None = None, path: str = "/") -> dict:
    return {"name": name, "value": value, "domain": domain, "path": path,
            "expires": expires if expires is not None else time.time() + 86400 * 5,
            "httpOnly": True, "secure": True, "sameSite": "Lax"}


class StateCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name)
        self.file = self.state / "storage-state.json"
        patches = [
            mock.patch.object(mozilib, "STORAGE_STATE_FILE", self.file),
            mock.patch.object(mozilib, "LAST_SEND_FILE", self.state / "last-send.json"),
            mock.patch.dict(os.environ, {"MOZI_TOKEN": "", "MOZI_BASE": ""}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def save(self, *cookies: dict) -> None:
        self.file.write_text(json.dumps({"cookies": list(cookies), "origins": []}),
                             encoding="utf-8")


class CookieHeader(StateCase):
    def test_the_header_comes_from_the_cookies_on_file_for_the_host(self):
        self.save(cookie(AEGIS, "tok"), cookie("other", "x", domain="example.com"),
                  cookie("portal_only", "p", domain="portal.acquisition.com"),
                  cookie("legacy_only", "l", domain="ai.acquisition.com"))
        self.assertEqual(mozilib.cookie_header(),
                         f"{AEGIS}=tok; portal_only=p")
        self.assertTrue(mozilib.has_session_cookie())

    def test_an_expired_cookie_is_left_out(self):
        self.save(cookie(AEGIS, "old", expires=time.time() - 10),
                  cookie("keep", "k", expires=-1))
        self.assertEqual(mozilib.cookie_header(), "keep=k")
        self.assertFalse(mozilib.has_session_cookie())

    def test_mozi_token_wins_when_set(self):
        self.save(cookie(AEGIS, "tok"))
        with mock.patch.dict(os.environ, {"MOZI_TOKEN": f"{AEGIS}=env"}):
            self.assertEqual(mozilib.cookie_header(), f"{AEGIS}=env")

    def test_no_file_is_an_empty_header(self):
        self.assertEqual(mozilib.cookie_header(), "")
        self.assertEqual(mozilib.session_expires_text(), "no login cookie on file")


class Expiry(StateCase):
    def test_the_session_cookie_names_its_expiry(self):
        exp = time.time() + 3 * 86400
        self.save(cookie("session_data", "d"), cookie(AEGIS, "tok", expires=exp))
        self.assertEqual(mozilib.session_cookie()["value"], "tok")
        self.assertAlmostEqual(mozilib.session_cookie_expires(), exp, delta=1)
        self.assertAlmostEqual(mozilib.session_expiry(), 3 * 86400, delta=2)
        text = mozilib.session_expires_text()
        self.assertIn(time.strftime("%Y-%m-%d", time.localtime(exp)), text)
        self.assertIn("3.0 days left", text)

    def test_hours_and_expired_read_as_such(self):
        self.save(cookie(AEGIS, "tok", expires=time.time() + 5 * 3600))
        self.assertIn("hours left", mozilib.session_expires_text())
        self.save(cookie(AEGIS, "tok", expires=time.time() - 60))
        self.assertIn("EXPIRED", mozilib.session_expires_text())
        self.assertLess(mozilib.session_expiry(), 0)

    def test_an_expired_cookie_stops_the_http_send_as_no_session(self):
        self.save(cookie(AEGIS, "tok", expires=time.time() - 60))
        with mock.patch.dict(os.environ, {"MOZI_SEND_OK": "1"}), \
                mock.patch.object(mozilib, "endpoint", return_value=ROUTE):
            with self.assertRaises(mozilib.MoziNoSession):
                mozilib.ask("Q")


class SetCookie(StateCase):
    def test_a_reply_cookie_replaces_the_one_on_file(self):
        old = cookie(AEGIS, "old", expires=time.time() + 100)
        self.save(old, cookie("keep", "k"))
        n = mozilib.store_set_cookies(
            [f"{AEGIS}=new; Domain=.acquisition.com; Path=/; Max-Age=600000; "
             "Secure; HttpOnly; SameSite=Lax"], "portal.acquisition.com")
        self.assertEqual(n, 1)
        names = {c["name"]: c for c in mozilib.stored_cookies()}
        self.assertEqual(names[AEGIS]["value"], "new")
        self.assertAlmostEqual(names[AEGIS]["expires"], time.time() + 600000, delta=5)
        self.assertEqual(names[AEGIS]["domain"], ".acquisition.com")
        self.assertTrue(names[AEGIS]["httpOnly"])
        self.assertEqual(names["keep"]["value"], "k")

    def test_an_expires_date_is_read_and_a_cleared_cookie_is_dropped(self):
        self.save(cookie(AEGIS, "tok"), cookie("gone", "g"))
        mozilib.store_set_cookies(
            [f"{AEGIS}=t2; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Path=/",
             "gone=; Max-Age=0; Path=/"], "portal.acquisition.com")
        names = {c["name"]: c for c in mozilib.stored_cookies()}
        self.assertNotIn("gone", names)
        self.assertEqual(names[AEGIS]["value"], "t2")
        # A cookie with no Domain belongs to the request host alone.
        self.assertEqual(names[AEGIS]["domain"], "portal.acquisition.com")
        import calendar
        self.assertEqual(names[AEGIS]["expires"],
                         calendar.timegm((2037, 10, 21, 7, 28, 0)))

    def test_nothing_is_written_without_a_login_on_file(self):
        self.assertEqual(mozilib.store_set_cookies(["a=b"], "portal.acquisition.com"), 0)
        self.assertFalse(self.file.exists())


class Request(StateCase):
    def test_no_cookie_on_file_is_no_session(self):
        with self.assertRaises(mozilib.MoziNoSession) as got:
            mozilib._request("POST", ROUTE["url"], body=b"{}")
        self.assertIn("login", str(got.exception))

    def test_a_401_is_no_session_and_its_cookies_are_kept(self):
        self.save(cookie(AEGIS, "tok"))
        import email.message
        headers = email.message.Message()
        headers["Set-Cookie"] = f"{AEGIS}=; Max-Age=0; Domain=.acquisition.com; Path=/"
        err = urllib.error.HTTPError(ROUTE["url"], 401, "Unauthorized", headers,
                                     io.BytesIO(b'{"message": "Unauthorized"}'))
        with mock.patch.object(mozilib.urllib.request, "urlopen", side_effect=err), \
                mock.patch.object(mozilib, "_pace"):
            with self.assertRaises(mozilib.MoziNoSession) as got:
                mozilib._request("POST", ROUTE["url"], body=b"{}")
        self.assertEqual(got.exception.status, 401)
        self.assertIn("Unauthorized", str(got.exception))
        self.assertEqual(mozilib.stored_cookies(), [], "the server cleared it")

    def test_a_429_is_blocked_but_not_no_session(self):
        self.save(cookie(AEGIS, "tok"))
        err = urllib.error.HTTPError(ROUTE["url"], 429, "Too Many", None, io.BytesIO(b""))
        with mock.patch.object(mozilib.urllib.request, "urlopen", side_effect=err), \
                mock.patch.object(mozilib, "_pace"):
            with self.assertRaises(mozilib.MoziBlocked) as got:
                mozilib._request("POST", ROUTE["url"], body=b"{}")
        self.assertNotIsInstance(got.exception, mozilib.MoziNoSession)
        self.assertEqual(got.exception.status, 429)

    def test_a_reply_sends_the_saved_cookies_and_keeps_new_ones(self):
        self.save(cookie(AEGIS, "tok"))
        seen = {}

        class Reply(io.BytesIO):
            status = 200

            def __init__(self):
                super().__init__(b'data: {"type":"text","text":"hi"}\n'
                                 b'data: {"type":"finish","finishReason":"stop"}\n')
                import email.message
                self.headers = email.message.Message()
                self.headers["Set-Cookie"] = (
                    f"{AEGIS}=fresh; Domain=.acquisition.com; Path=/; Max-Age=86400")

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def urlopen(req, timeout=0):
            seen["cookie"] = req.get_header("Cookie")
            return Reply()

        with mock.patch.object(mozilib.urllib.request, "urlopen", side_effect=urlopen), \
                mock.patch.object(mozilib, "_pace"):
            status, raw = mozilib._request("POST", ROUTE["url"], body=b"{}")
        self.assertEqual(status, 200)
        self.assertEqual(seen["cookie"], f"{AEGIS}=tok")
        self.assertEqual(mozilib.session_cookie()["value"], "fresh")
        self.assertEqual(mozilib.extract_answer(raw, ROUTE), "hi")


class Pacing(StateCase):
    """One send at a time, paced from the last send on file, so the floor
    holds across separate runs and both transports."""

    def setUp(self):
        super().setUp()
        mozilib._last_request = 0.0
        self.addCleanup(setattr, mozilib, "_last_request", 0.0)
        self.slept = []
        for p in (mock.patch.object(mozilib.time, "sleep", side_effect=self.slept.append),
                  mock.patch.object(mozilib.random, "uniform", return_value=20.0),
                  mock.patch.dict(os.environ, {"MOZI_MIN_DELAY": "12", "MOZI_MAX_DELAY": "30"})):
            p.start()
            self.addCleanup(p.stop)

    def test_the_first_send_waits_for_nothing_and_is_stamped(self):
        with contextlib.redirect_stderr(io.StringIO()):
            mozilib._pace("HTTP")
        self.assertEqual(self.slept, [])
        last = mozilib.last_send()
        self.assertAlmostEqual(last["at"], time.time(), delta=2)
        self.assertEqual(last["transport"], "HTTP")
        self.assertIsNone(last["ok"])

    def test_a_send_five_seconds_after_the_last_on_file_waits_the_rest(self):
        mozilib._write_last_send({"at": time.time() - 5, "ok": True})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            mozilib._pace("browser")
        self.assertEqual(len(self.slept), 1)
        self.assertAlmostEqual(self.slept[0], 15.0, delta=1)
        self.assertIn("pacing 15s", err.getvalue())
        self.assertEqual(mozilib.last_send()["transport"], "browser")

    def test_a_send_long_after_the_last_waits_for_nothing(self):
        mozilib._write_last_send({"at": time.time() - 100, "ok": True})
        with contextlib.redirect_stderr(io.StringIO()):
            mozilib._pace("HTTP")
        self.assertEqual(self.slept, [])

    def test_the_later_of_the_file_and_this_process_counts(self):
        mozilib._write_last_send({"at": time.time() - 100, "ok": True})
        mozilib._last_request = time.monotonic() - 2
        with contextlib.redirect_stderr(io.StringIO()):
            mozilib._pace("HTTP")
        self.assertEqual(len(self.slept), 1)
        self.assertAlmostEqual(self.slept[0], 18.0, delta=1)

    def test_the_http_ask_paces_once_for_create_and_post(self):
        self.save(cookie(AEGIS, "tok"))
        paced = []
        with mock.patch.dict(os.environ, {"MOZI_SEND_OK": "1"}), \
                mock.patch.object(mozilib, "endpoint", return_value=ROUTE), \
                mock.patch.object(mozilib, "CHAT_ID_FILE", self.state / "chat-id"), \
                mock.patch.object(mozilib, "_pace", side_effect=paced.append), \
                mock.patch.object(mozilib, "_request", side_effect=[
                    (200, b'{"id": "c9"}'),
                    (200, b'data: {"type":"text","text":"A"}\n'
                          b'data: {"type":"finish","finishReason":"stop"}\n')]), \
                contextlib.redirect_stderr(io.StringIO()):
            answer, chat = mozilib.ask("Q")
        self.assertEqual(answer, "A")
        self.assertEqual(paced, ["HTTP"], "one pace for the chat create and the post")


class SendFallsBack(StateCase):
    """send tries HTTP first and goes to the browser only when HTTP has no
    session. Both transports are fakes here."""

    def setUp(self):
        super().setUp()
        self.answers = self.state / "answers"
        self.answers.mkdir()
        self.err = io.StringIO()
        self.out = io.StringIO()
        self.hops = []

    def send(self, argv, *, http=None, browser=None, route=ROUTE):
        import mozi_browser

        def hop(args, stdin_text=None):
            self.hops.append(list(args))
            return None

        with mock.patch.dict(os.environ), \
                mock.patch.object(acqai, "ANSWERS", self.answers), \
                mock.patch.object(acqai, "NAMES_FILE", self.state / "names"), \
                mock.patch.object(acqai, "_under_venv", side_effect=hop), \
                mock.patch.object(mozilib, "endpoint", return_value=route), \
                mock.patch.object(mozilib, "CHAT_ID_FILE", self.state / "chat-id"), \
                mock.patch.object(mozilib, "ask", side_effect=http), \
                mock.patch.object(mozi_browser, "send", side_effect=browser), \
                contextlib.redirect_stdout(self.out), \
                contextlib.redirect_stderr(self.err):
            return acqai.main(argv)

    def test_http_answers_and_no_browser_opens(self):
        browser = mock.Mock()
        code = self.send(["send", "Q", "-y"],
                         http=lambda m, chat_id=None, timeout=120: ("A", "c1@portal.acquisition.com"),
                         browser=browser)
        self.assertEqual(code, 0, self.err.getvalue())
        browser.assert_not_called()
        self.assertEqual(self.hops, [])
        filed = next(self.answers.glob("*.md")).read_text(encoding="utf-8")
        self.assertIn("via HTTP", filed)
        self.assertIn("sending via HTTP", self.err.getvalue())

    def test_no_session_falls_back_to_the_browser(self):
        code = self.send(["send", "Q", "-y"],
                         http=mozilib.MoziNoSession("401 from mozi", 401),
                         browser=lambda m, chat_id=None: ("B", "c2@portal.acquisition.com"))
        self.assertEqual(code, 0, self.err.getvalue())
        self.assertEqual(self.hops, [["send", "Q", "-y", "--browser"]])
        self.assertIn("falling back to your browser", self.err.getvalue())
        filed = next(self.answers.glob("*.md")).read_text(encoding="utf-8")
        self.assertIn("via browser", filed)

    def test_http_only_stops_on_no_session(self):
        browser = mock.Mock()
        code = self.send(["send", "Q", "-y", "--http"],
                         http=mozilib.MoziNoSession("no cookie"), browser=browser)
        self.assertEqual(code, 1)
        browser.assert_not_called()
        self.assertIn("stopped (no cookie)", self.err.getvalue())

    def test_another_http_error_does_not_fall_back(self):
        browser = mock.Mock()
        code = self.send(["send", "Q", "-y"],
                         http=mozilib.MoziError("500 on the route"), browser=browser)
        self.assertEqual(code, 1)
        browser.assert_not_called()
        self.assertEqual(self.hops, [])

    def test_browser_only_skips_http(self):
        http = mock.Mock()
        code = self.send(["send", "Q", "-y", "--browser"], http=http,
                         browser=lambda m, chat_id=None: ("B", None))
        self.assertEqual(code, 0, self.err.getvalue())
        http.assert_not_called()

    def ask(self, argv, *, route=ROUTE, fresh=True, **kw):
        """ask with the login fresh (or not) and ready's browser step replaced."""
        import mozi_browser
        if fresh:
            self.save(cookie(AEGIS, "tok"))
            mozilib.record_send(True, "HTTP")
        check = mock.Mock()
        with mock.patch.object(acqai, "_playwright_here", return_value=True), \
                mock.patch.object(mozi_browser, "STATE_FILE", self.file), \
                mock.patch.object(mozi_browser, "require_session", check):
            code = self.send(argv, route=route, **kw)
        return code, check

    def test_ask_is_ready_then_send_in_one_run(self):
        code, check = self.ask(
            ["ask", "Q", "-y"],
            http=lambda m, chat_id=None, timeout=120: ("A", "c1@portal.acquisition.com"),
            browser=mock.Mock())
        self.assertEqual(code, 0, self.err.getvalue())
        check.assert_not_called()
        self.assertIn("ready (login cookie expires", self.err.getvalue())
        self.assertIn("sending via HTTP", self.err.getvalue())
        self.assertNotIn("ready: ask with", self.out.getvalue(), "no probe dump")
        filed = next(self.answers.glob("*.md")).read_text(encoding="utf-8")
        self.assertIn("acqai.py send Q -y", filed, "filed as the send it ran")

    def test_ask_stops_where_ready_stops(self):
        http = mock.Mock()
        code, check = self.ask(["ask", "Q", "-y"], route=None, http=http,
                               browser=mock.Mock())
        self.assertEqual(code, 1)
        http.assert_not_called()

    def test_the_dry_run_names_both_paths(self):
        self.save(cookie(AEGIS, "tok"))
        code = self.send(["send", "Q", "--dry-run"], http=mock.Mock(), browser=mock.Mock())
        self.assertEqual(code, 0)
        self.assertIn("HTTP with the saved login, then your browser", self.out.getvalue())


if __name__ == "__main__":
    unittest.main()
