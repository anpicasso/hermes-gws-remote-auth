"""Offline login flow: fake gws speaks the same localhost protocol."""
import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from util import plugin, route, backend_module
from importlib import import_module
oauth = import_module(plugin.__name__ + ".oauth")



FAKE_GWS = '''#!{python}
import json, os, socket, sys
from pathlib import Path
if sys.argv[1:3] == ["auth", "status"]:
    p = Path(os.environ["GOOGLE_WORKSPACE_CLI_CONFIG_DIR"])
    user = (p / "fake-user").read_text()
    print(json.dumps({"token_valid": True, "user": user if user != "(unknown)" else None}))
    sys.exit(0)
if sys.argv[1:3] == ["auth", "logout"]:
    (Path(os.environ["GOOGLE_WORKSPACE_CLI_CONFIG_DIR"]) / "credentials.enc").unlink(missing_ok=True)
    sys.exit(0)
if sys.argv[1:3] != ["auth", "login"]:
    sys.exit(2)
dir = Path(os.environ["GOOGLE_WORKSPACE_CLI_CONFIG_DIR"])
try:
    client = json.loads((dir / "client_secret.json").read_text())["installed"]
    assert client["client_id"] and client["client_secret"]
except (OSError, KeyError, ValueError, AssertionError):
    sys.exit(2)
assert Path(os.environ["HOME"]).parent == dir
assert Path(".env").read_bytes() == b""
assert not any(k in os.environ for k in ("GOOGLE_WORKSPACE_CLI_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_CONFIG", "FAKE_ACCOUNT"))
(dir / "argv.json").write_text(json.dumps(sys.argv[1:]))
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
sock.listen(1)
port = sock.getsockname()[1]
print("Open this URL in your browser to authenticate:", flush=True)
sys.stdout.write("https://accounts.google.com/o/oauth2/auth?client_id=fake&redirect_uri=http%3A%2F%2Flocalhost%3A")
sys.stdout.flush()
import time
time.sleep(0.05)
print(str(port) + "&scope=openid", flush=True)
conn, _ = sock.accept()
request = conn.recv(4096).decode()
conn.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nOK")
conn.close()
sock.close()
code = request.split("code=", 1)[1].split(" ", 1)[0].split("&", 1)[0] if "code=" in request else ""
if code not in ("good", "alpha", "beta"):
    sys.exit(1)
(dir / "credentials.enc").write_text(code)
(dir / "fake-user").write_text(client.get("test_identity", "user@example.com"))
print(json.dumps({"status": "success", "account": os.environ.get("FAKE_ACCOUNT", "user@example.com")}), flush=True)
'''


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        for account in ("user@example.com", "other@example.com", "full@example.com"):
            self.provision(self.home, account)
        self.fake = self.home / "fake-gws"
        self.fake.write_text(FAKE_GWS.replace("{python}", sys.executable))
        self.fake.chmod(0o700)
        self.check_lifecycle = lambda root, account: None
        self.backends = {}
        self.manager = self.new_manager()
        self.addCleanup(self.manager.close)
        self.handles = []

    @staticmethod
    def provision(root, account="user@example.com", user="user@example.com"):
        slot = root / "accounts" / account
        slot.mkdir(parents=True, exist_ok=True)
        (slot / "client_secret.json").write_text(json.dumps({"installed": {
            "client_id": "fake", "client_secret": "fixture", "test_identity": user}}))
        return slot

    def slot(self, account="user@example.com"):
        return self.home / "accounts" / account

    def assert_blocked(self, account="user@example.com"):
        self.assertFalse(self.backends[self.home].registered(account))
        self.assertTrue((self.slot(account) / ".hermes-unverified").is_file())

    def new_manager(self):
        def backend(root):
            root = Path(root).absolute()
            def check(args):
                self.check_lifecycle(root, args["account"])
                return {"ok": True, "contract": "gws-account-lifecycle-v1", "account": args["account"],
                        "credentials_in_use": False}
            if root not in self.backends:
                self.backends[root] = backend_module.AccountBackend(root, lambda: str(self.fake), check)
            return self.backends[root]
        return oauth.LoginManager(backend=backend, callback_root=lambda: self.home)

    def register(self, callback):
        handle = SimpleNamespace(active=True)
        def dispose():
            handle.active = False
        handle.dispose = dispose
        async def ingress(event, **kwargs):
            store = SimpleNamespace(_generate_session_key=lambda source: route(source.chat_id)[1],
                                    peek_session_id=lambda key: route(event.source.chat_id)[2])
            return await callback(event, session_store=store, **kwargs)
        self.handles.append((handle, ingress))
        return handle

    def start(self, user="42", timeout: float = 10, **kwargs):
        return self.manager.start(
            self.home, "telegram", route("100"), user, "user@example.com", self.register, timeout=timeout, **kwargs,
        )

    def seed_account(self, account="user@example.com", content="old-credentials"):
        directory = self.home / "accounts" / account
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "credentials.enc").write_text(content)
        return directory

    def finish_with(self, result, code="good", user="42"):
        from urllib.parse import parse_qs, urlsplit
        redirect = parse_qs(urlsplit(result["url"]).query)["redirect_uri"][0]
        return asyncio.run(self.handles[0][1](event=self.event(redirect + "?code=" + code, user=user)))

    def event(self, text, user="42"):
        return SimpleNamespace(text=text, source=SimpleNamespace(
            platform=SimpleNamespace(value="telegram"), chat_id="100", user_id=user,
            chat_type="dm", profile="", message_id="321"))

    def test_login_rewrites_only_matching_callback_and_registers_account(self):
        result = self.start()
        self.assertTrue(result["ok"])
        attempt = next(iter(self.manager._attempts.values()))
        self.assertEqual(json.loads((self.slot(attempt.account) / "argv.json").read_text()),
                         ["auth", "login", "--full"])
        from urllib.parse import parse_qs, urlsplit
        redirect = parse_qs(urlsplit(result["url"]).query)["redirect_uri"][0]
        self.assertEqual(len(self.handles), 1)
        callback = self.handles[0][1]
        self.assertIsNone(asyncio.run(callback(event=self.event("hello"))))
        self.assertIsNone(asyncio.run(callback(event=self.event(redirect + "?code=good", user="other"))))
        deletes = []
        async def delete_message(chat_id, message_id):
            deletes.append((chat_id, message_id))
            return True
        gateway = SimpleNamespace(_delivery_adapter_for_source=None,
                                  _delivery_adapter_for=lambda source: SimpleNamespace(delete_message=delete_message))
        response = asyncio.run(callback(event=self.event(redirect + "?code=good"), gateway=gateway))
        self.assertEqual(deletes, [("100", "321")])
        self.assertEqual(response["action"], "rewrite")
        self.assertIn("user@example.com", response["text"])
        self.assertNotIn("code=", response["text"])
        self.assertTrue((self.home / "accounts" / "user@example.com" / "credentials.enc").exists())
        self.assertFalse(self.handles[0][0].active)

    def test_callback_without_scheme_is_accepted(self):
        result = self.start()
        from urllib.parse import parse_qs, urlsplit
        redirect = parse_qs(urlsplit(result["url"]).query)["redirect_uri"][0]
        callback = self.handles[0][1]

        response = asyncio.run(callback(event=self.event(
            (redirect + "?code=good").removeprefix("http://")
        )))

        self.assertEqual(response["action"], "rewrite")
        self.assertIn("user@example.com", response["text"])
        self.assertNotIn("code=", response["text"])
        self.assertTrue((self.home / "accounts" / "user@example.com" / "credentials.enc").exists())

    def test_callback_audit_rejects_ambiguous_queries_without_exchange(self):
        self.assertTrue(self.start()["ok"])
        attempt = self.pending()
        with mock.patch.object(self.manager, "_run_exchange") as exchange:
            for suffix in ("?code=good&code=", "?code=good&error=", "?code=good&error=access_denied",
                           "?error=access_denied&error=", "?code=good#", "?code=go\nod"):
                with self.subTest(suffix=suffix):
                    result = self.manager.finish(self.home, "telegram", route("100"), "42", "user@example.com",
                                                 attempt.redirect + suffix)
                    self.assertEqual(result.get("reason"), "invalid_callback")
                    self.assertTrue(result.get("retryable"))
            exchange.assert_not_called()
        self.assertIsNone(attempt.process.poll())

    def test_callback_audit_scopes_malformed_urls_before_rewriting(self):
        self.start()
        for text in ("http://localhost:bad/?code=fixture", "http://localhost:" + "x" * 9000):
            event = self.event(text)
            event.source.profile = "other"
            self.assertIsNone(asyncio.run(self.handles[0][1](event)))

    def test_callback_audit_deletes_malformed_paste_best_effort(self):
        self.start()
        delete = mock.AsyncMock(side_effect=RuntimeError("synthetic deletion failure"))
        gateway = SimpleNamespace(_delivery_adapter_for=lambda source: SimpleNamespace(delete_message=delete))
        response = asyncio.run(self.handles[0][1](
            self.event("http://localhost:bad/?code=fixture"), gateway=gateway))
        self.assertEqual(response["action"], "rewrite")
        self.assertNotIn("fixture", response["text"])
        delete.assert_awaited_once_with("100", "321")

    def test_callback_audit_shared_validation_and_cancellation_redaction(self):
        self.start()
        attempt = self.pending()
        for suffix in ("/wrong?code=fixture", "?code=fixture&code=", "?code=fixture#",
                       "?code=fixture&" + "&".join(f"x{i}=y" for i in range(33))):
            with self.subTest(suffix=suffix):
                url = attempt.redirect + suffix
                explicit = self.manager.finish(self.home, "telegram", route("100"), "42", "user@example.com", url)
                intercepted = asyncio.run(self.handles[0][1](self.event(url)))
                self.assertTrue(explicit.get("retryable"))
                self.assertIn(explicit["error"], intercepted["text"])
                self.assertNotIn("fixture", intercepted["text"])
        url = attempt.redirect.replace("//localhost", "//@localhost") + "?code=fixture"
        self.assertEqual(self.manager.finish(self.home, "telegram", route("100"), "42", "user@example.com", url)["reason"],
                         "invalid_callback")
        with mock.patch.object(oauth.asyncio, "to_thread", side_effect=asyncio.CancelledError):
            result = asyncio.run(self.handles[0][1](self.event(attempt.redirect + "?code=fixture")))
        self.assertEqual(result["action"], "rewrite")
        self.assertNotIn("fixture", result["text"])
        self.assertIsNone(attempt.process.poll())

    def test_callback_audit_case_insensitive_endpoint(self):
        self.start()
        url = self.pending().redirect.replace("http://localhost", "HTTP://LOCALHOST") + "?code=good"
        response = asyncio.run(self.handles[0][1](self.event(url)))
        self.assertIsNotNone(response)
        self.assertIn("user@example.com", response["text"])

    def test_fresh_slot_is_created_without_reading_global_or_profile_client(self):
        root = self.home / "fresh-profile" / "gws-oauth"
        root.mkdir(parents=True)
        (root / "client_secret.json").write_text("synthetic-profile-client")
        result = self.manager.start(root, "cli", route("s"), "42", "user@example.com", None)
        self.assertEqual(result["reason"], "launch_failed")
        self.assertIn("hermes gws setup", result["error"])
        slot = root / "accounts/user@example.com"
        self.assertTrue(slot.is_dir())
        self.assertFalse((slot / "client_secret.json").exists())

    def test_custom_scopes_are_forwarded_to_gws(self):
        scopes = ["openid", "https://www.googleapis.com/auth/drive.readonly"]
        result = self.manager.start(
            self.home, "telegram", route("100"), "42", "user@example.com", self.register, timeout=10, scope_mode="custom", scopes=scopes,
        )
        self.assertTrue(result["ok"])
        attempt = next(iter(self.manager._attempts.values()))
        self.assertEqual(json.loads((self.slot(attempt.account) / "argv.json").read_text()),
                         ["auth", "login", "--scopes", ",".join(scopes)])

    def test_timeout_stops_process_and_unhooks(self):
        result = self.start(timeout=0.3)
        self.assertTrue(result["ok"])
        from time import sleep
        sleep(0.7)
        self.assertFalse(self.handles[0][0].active)
        self.assertFalse(self.manager.has_pending(self.home, "telegram", route("100"), "42"))

    def test_malformed_owned_callback_never_reaches_agent(self):
        self.start()
        callback = self.handles[0][1]
        response = asyncio.run(callback(event=self.event("http://localhost:invalid/?code=should-not-leak")))
        self.assertEqual(response["action"], "rewrite")
        self.assertNotIn("should-not-leak", response["text"])
        oversized = asyncio.run(callback(event=self.event("http://localhost:" + "x" * 9000 + "?code=secret")))
        self.assertEqual(oversized["action"], "rewrite")
        self.assertNotIn("secret", oversized["text"])

    def test_callback_for_another_profile_cannot_finish_login(self):
        result = self.start()
        from urllib.parse import parse_qs, urlsplit
        redirect = parse_qs(urlsplit(result["url"]).query)["redirect_uri"][0]
        callback = self.handles[0][1]
        other_profile = self.event(redirect + "?code=good")
        other_profile.source.profile = "other"
        self.assertIsNone(asyncio.run(callback(event=other_profile)))
        self.assertTrue(self.manager.has_pending(self.home, "telegram", route("100"), "42"))

    def test_timeout_does_not_delete_files_under_active_exchange(self):
        import threading
        from time import sleep
        self.start(timeout=0.3)
        from urllib.parse import parse_qs, urlsplit
        attempt = next(iter(self.manager._attempts.values()))
        redirect = attempt.redirect
        entered, proceed = threading.Event(), threading.Event()
        original = self.manager._fetch_and_commit
        def delayed(attempt, code, root):
            entered.set()
            proceed.wait(2)
            return original(attempt, code, root)
        self.manager._fetch_and_commit = delayed
        result = []
        worker = threading.Thread(target=lambda: result.append(asyncio.run(
            self.handles[0][1](event=self.event(redirect + "?code=good")))))
        worker.start()
        self.assertTrue(entered.wait(2))
        sleep(0.45)
        self.assertTrue(self.slot(attempt.account).is_dir())
        proceed.set()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertIn("could not be completed", result[0]["text"])
        self.assert_blocked()

    def test_hook_registration_failure_does_not_leave_attempt(self):
        def broken(_callback):
            raise RuntimeError("registration failed")
        result = self.manager.start(self.home, "telegram", route("100"), "42", "user@example.com",
                                    broken, timeout=1)
        self.assertFalse(result["ok"])
        self.assertFalse(self.manager.has_pending(self.home, "telegram", route("100"), "42"))

    def test_wrong_google_identity_cannot_become_registered_account(self):
        result = self.manager.start(self.home, "telegram", route("100"), "42", "other@example.com",
                                    self.register, timeout=10)
        from urllib.parse import parse_qs, urlsplit
        redirect = parse_qs(urlsplit(result["url"]).query)["redirect_uri"][0]
        response = asyncio.run(self.handles[0][1](event=self.event(redirect + "?code=good")))
        self.assertEqual(response["action"], "rewrite")
        self.assertIn("could not be completed", response["text"])
        self.assert_blocked("other@example.com")

    def test_any_surface_finishes_without_hook_and_is_session_bound(self):
        for platform in ("cli", "tui", "desktop", "api_server", "custom_ui", "telegram"):
            with self.subTest(platform=platform):
                root = self.home / platform
                root.mkdir()
                self.provision(root)
                result = self.manager.start(root, platform, route("session-1"), "local", "user@example.com",
                                            None, timeout=10, profile="default")
                self.assertTrue(result["ok"])
                self.assertEqual(self.handles, [], "terminal chat must not register an interception hook")
                attempt = next(iter(self.manager._attempts.values()))
                callback = (attempt.redirect + "?code=good").removeprefix("http://")
                for target, session, profile, account in (
                    (root, "session-2", "default", "user@example.com"),
                    (root, "session-1", "other", "user@example.com"),
                    (self.home, "session-1", "default", "user@example.com"),
                    (root, "session-1", "default", "other@example.com"),
                ):
                    self.assertFalse(self.manager.finish(target, platform, route(session), "local", account,
                                                         callback, profile=profile)["ok"])
                self.assertFalse(self.manager.finish(root, "other_surface", route("session-1"), "local",
                                                     "user@example.com", callback, profile="default")["ok"])
                self.assertFalse(self.manager.finish(root, platform, route("session-1"), "another-user",
                                                     "user@example.com", callback, profile="default")["ok"])
                for invalid in ("https://example.com/?code=good", "http://localhost:invalid/?code=good",
                                attempt.redirect + "/wrong?code=good", "x" * 8193, None):
                    self.assertFalse(self.manager.finish(root, platform, route("session-1"), "local", "user@example.com",
                                                         invalid, profile="default")["ok"])
                response = self.manager.finish(root, platform, route("session-1"), "local", "user@example.com",
                                               callback, profile="default")
                self.assertTrue(response["ok"], response)
                self.assertNotIn("code=", json.dumps(response))
                self.assertTrue((root / "accounts" / "user@example.com" / "credentials.enc").is_file())
                self.assertFalse(self.manager._attempts)
                self.assertFalse(self.manager.finish(root, platform, route("session-1"), "local", "user@example.com",
                                                     callback, profile="default")["ok"])

    def test_terminal_chat_rejects_invalid_codes_and_wrong_google_identity(self):
        for account, query in (("user@example.com", "?code=bad"),
                               ("other@example.com", "?code=good")):
            with self.subTest(account=account, query=query):
                result = self.manager.start(self.home, "cli", route("session-1"), "local", account,
                                            None, timeout=10)
                self.assertTrue(result["ok"])
                attempt = next(iter(self.manager._attempts.values()))
                response = self.manager.finish(self.home, "cli", route("session-1"), "local", account,
                                               attempt.redirect + query)
                self.assertFalse(response["ok"])
                self.assert_blocked(account)
                self.assertIsNotNone(attempt.process.poll())
                self.assertFalse(self.manager._attempts)

    def test_existing_account_requires_explicit_reauthorize(self):
        account = self.seed_account()
        result = self.start()
        self.assertFalse(result["ok"])
        self.assertIn("reauthorize=true", result["error"])
        self.assertEqual((account / "credentials.enc").read_text(), "old-credentials")
        self.assertFalse(self.manager._attempts)

    def test_reauthorize_rejects_non_boolean_flags(self):
        account = self.seed_account()
        for value in ("false", "true", 1, None):
            self.assertFalse(self.start(reauthorize=value)["ok"])
        self.assertEqual((account / "credentials.enc").read_text(), "old-credentials")
        self.assertFalse(self.manager._attempts)

    def test_symlinked_destination_is_rejected_before_launch(self):
        slot = self.seed_account()
        moved = slot.with_name("preserved")
        slot.rename(moved)
        slot.symlink_to(moved, target_is_directory=True)
        with mock.patch.object(oauth.subprocess, "Popen") as spawn:
            self.assertFalse(self.start(reauthorize=True)["ok"])
            spawn.assert_not_called()
        self.assertEqual((moved / "credentials.enc").read_text(), "old-credentials")

    def test_reauthorize_writes_directly_to_the_same_native_store(self):
        account = self.seed_account()
        result = self.start(reauthorize=True)
        self.assertTrue(result["ok"])
        self.assertEqual((account / "credentials.enc").read_text(), "old-credentials")

        response = self.finish_with(result, "good")

        self.assertEqual(response["action"], "rewrite")
        self.assertIn("user@example.com", response["text"])
        self.assertNotIn("code=", response["text"])
        self.assertEqual((account / "credentials.enc").read_text(), "good")
        self.assertFalse(list((self.home / "accounts").glob(".*.backup-*")))

    def test_reauthorize_identity_mismatch_blocks_replacement(self):
        account = self.seed_account("other@example.com")
        result = self.manager.start(
            self.home, "telegram", route("100"), "42", "other@example.com", self.register, timeout=10, reauthorize=True,
        )
        self.assertTrue(result["ok"])

        response = self.finish_with(result, "good")

        self.assertEqual(response["action"], "rewrite")
        self.assertIn("could not be completed", response["text"])
        self.assertEqual((account / "credentials.enc").read_text(), "good")
        self.assert_blocked(account.name)
        self.assertFalse(self.manager._attempts)

    def test_reauthorize_cancelled_flow_leaves_old_credentials(self):
        account = self.seed_account()
        result = self.start(reauthorize=True)
        self.assertTrue(result["ok"])

        response = self.finish_with(result, "bad")

        self.assertEqual(response["action"], "rewrite")
        self.assertIn("could not be completed", response["text"])
        self.assertEqual((account / "credentials.enc").read_text(), "old-credentials")
        self.assertFalse(self.manager._attempts)

    def test_reauthorize_timeout_leaves_old_credentials(self):
        from time import sleep
        account = self.seed_account()
        result = self.start(timeout=0.3, reauthorize=True)
        self.assertTrue(result["ok"])

        sleep(0.7)

        self.assertEqual((account / "credentials.enc").read_text(), "old-credentials")
        self.assertFalse(self.manager.has_pending(self.home, "telegram", route("100"), "42"))

    def test_overlapping_reauthorize_refuses_second_writer(self):
        account = self.seed_account()
        first = self.start(user="42", reauthorize=True)
        self.assertTrue(first["ok"])
        self.assertEqual(self.start(user="43", reauthorize=True)["reason"], "account_busy")
        self.assert_blocked()
        self.finish_with(first, "alpha", user="42")
        self.assertTrue(self.backends[self.home].registered(account.name))
        self.assertEqual((account / "credentials.enc").read_text(), "alpha")

    def test_same_port_different_path_is_rejected_and_expired_attempt_not_reused(self):
        result = self.start()
        from urllib.parse import parse_qs, urlsplit
        redirect = parse_qs(urlsplit(result["url"]).query)["redirect_uri"][0]
        callback = self.handles[0][1]
        wrong_path = asyncio.run(callback(event=self.event(redirect + "/other?code=good")))
        self.assertEqual(wrong_path["action"], "rewrite")
        self.assertNotIn("code=", wrong_path["text"])
        failure = asyncio.run(callback(event=self.event(redirect + "?code=bad")))
        self.assertEqual(failure["action"], "rewrite")
        self.assertNotIn("code=", failure["text"])
        self.assertIn("gws_failed", failure["text"])
        self.assertFalse(self.manager.has_pending(self.home, "telegram", route("100"), "42"))

    # --- local browser: the redirect reaches the gws loopback without any paste ---

    def browser_hits_loopback(self, attempt, code="good"):
        """Simulate a browser on the Hermes host following the redirect itself."""
        import http.client
        from urllib.parse import urlsplit
        conn = http.client.HTTPConnection("127.0.0.1", urlsplit(attempt.redirect).port, timeout=3)
        conn.request("GET", "/?code=" + code)
        conn.getresponse().read()
        conn.close()
        self.assertTrue(attempt.done.wait(5), "watcher must finish the local exchange")

    def test_local_browser_completion_registers_account_without_paste(self):
        result = self.start()
        key, attempt = next(iter(self.manager._attempts.items()))
        self.browser_hits_loopback(attempt)
        self.assertTrue((self.home / "accounts" / "user@example.com" / "credentials.enc").is_file())
        self.assertFalse(list(self.slot(attempt.account).glob(".exec-home-*")))
        self.assertTrue(attempt.finished)
        self.assertTrue(attempt.result["ok"])
        self.assertTrue(attempt.result["local_browser"])
        # The attempt stays registered so the hook still swallows a late paste.
        self.assertTrue(self.manager.has_pending(self.home, "telegram", route("100"), "42"))
        self.assertTrue(self.handles[0][0].active)

    def test_local_browser_outcome_is_handed_over_by_status_call_once(self):
        self.start()
        attempt = next(iter(self.manager._attempts.values()))
        self.browser_hits_loopback(attempt)
        status = self.start()
        self.assertTrue(status["ok"], status)
        self.assertTrue(status["consumed"])
        self.assertIn("user@example.com", status["message"])
        self.assertFalse(self.manager._attempts)
        self.assertFalse(self.handles[0][0].active)
        again = self.start()
        self.assertFalse(again["ok"])
        self.assertIn("reauthorize=true", again["error"])

    def test_late_paste_after_local_completion_is_rewritten_with_stored_outcome(self):
        result = self.start()
        attempt = next(iter(self.manager._attempts.values()))
        self.browser_hits_loopback(attempt)
        response = self.finish_with(result, "good")
        self.assertEqual(response["action"], "rewrite")
        self.assertIn("user@example.com", response["text"])
        self.assertIn("local browser", response["text"])
        self.assertNotIn("code=", response["text"])
        self.assertFalse(self.manager._attempts)
        self.assertTrue((self.home / "accounts" / "user@example.com" / "credentials.enc").is_file())

    def test_local_browser_identity_mismatch_is_reported_and_routing_blocked(self):
        result = self.manager.start(self.home, "telegram", route("100"), "42", "other@example.com",
                                    self.register, timeout=10)
        self.assertTrue(result["ok"])
        attempt = next(iter(self.manager._attempts.values()))
        self.browser_hits_loopback(attempt)
        self.assertFalse(attempt.result["ok"])
        self.assertEqual(attempt.result["reason"], "identity_mismatch")
        self.assertEqual((self.slot(attempt.account) / "credentials.enc").read_text(), "good")
        self.assert_blocked("other@example.com")
        status = self.manager.start(self.home, "telegram", route("100"), "42", "other@example.com",
                                    self.register, timeout=10)
        self.assertFalse(status["ok"])
        self.assertEqual(status["reason"], "identity_mismatch")
        self.assertIn("could not be completed", status["error"])
        fresh = self.manager.start(self.home, "telegram", route("100"), "42", "other@example.com",
                                   self.register, timeout=10, reauthorize=True)
        self.assertTrue(fresh["ok"], "a consumed failure must not block a new login")

    def test_local_browser_cancelled_consent_is_reported_as_gws_failure(self):
        self.start()
        attempt = next(iter(self.manager._attempts.values()))
        self.browser_hits_loopback(attempt, code="bad")
        self.assertEqual(attempt.result["reason"], "gws_failed")
        self.assertFalse(list(self.slot(attempt.account).glob(".exec-home-*")))
        self.assert_blocked()

    def test_local_completion_is_released_at_deadline_and_account_survives(self):
        from time import sleep
        self.start(timeout=0.6)
        attempt = next(iter(self.manager._attempts.values()))
        self.browser_hits_loopback(attempt)
        sleep(1.0)
        self.assertFalse(self.manager.has_pending(self.home, "telegram", route("100"), "42"))
        self.assertFalse(self.handles[0][0].active)
        self.assertTrue((self.home / "accounts" / "user@example.com" / "credentials.enc").is_file())

    def test_paste_while_watcher_is_committing_waits_for_single_outcome(self):
        import threading
        from time import sleep
        result = self.start()
        attempt = next(iter(self.manager._attempts.values()))
        entered, proceed = threading.Event(), threading.Event()
        original = self.manager._fetch_and_commit
        commits = []
        def delayed(attempt, code, root):
            commits.append(code)
            entered.set()
            proceed.wait(3)
            return original(attempt, code, root)
        self.manager._fetch_and_commit = delayed
        # Local browser reaches the loopback; the watcher enters the exchange and blocks.
        import http.client
        from urllib.parse import urlsplit
        conn = http.client.HTTPConnection("127.0.0.1", urlsplit(attempt.redirect).port, timeout=3)
        conn.request("GET", "/?code=good")
        conn.getresponse().read()
        conn.close()
        self.assertTrue(entered.wait(3))
        outcome = []
        paster = threading.Thread(target=lambda: outcome.append(self.finish_with(result, "good")))
        paster.start()
        sleep(0.3)
        self.assertTrue(paster.is_alive(), "a paste racing the watcher must wait, not race")
        self.assertEqual(commits, [None], "only the watcher runs the exchange")
        proceed.set()
        paster.join(5)
        self.assertFalse(paster.is_alive())
        self.assertEqual(commits, [None])
        self.assertIn("user@example.com", outcome[0]["text"])
        self.assertIn("local browser", outcome[0]["text"])
        self.assertTrue((self.home / "accounts" / "user@example.com" / "credentials.enc").is_file())
        self.assertFalse(self.manager._attempts)

    def test_deadline_never_closes_stdout_of_exited_process_under_watcher(self):
        import threading
        from time import sleep
        self.start(timeout=0.4)
        attempt = next(iter(self.manager._attempts.values()))
        entered, proceed = threading.Event(), threading.Event()
        original = self.manager._fetch_and_commit
        def delayed(attempt, code, root):
            entered.set()
            proceed.wait(3)
            return original(attempt, code, root)
        self.manager._fetch_and_commit = delayed
        import http.client
        from urllib.parse import urlsplit
        conn = http.client.HTTPConnection("127.0.0.1", urlsplit(attempt.redirect).port, timeout=3)
        conn.request("GET", "/?code=good")
        conn.getresponse().read()
        conn.close()
        self.assertTrue(entered.wait(3))
        sleep(0.6)  # deadline timer fires while the watcher owns the exited process
        self.assertTrue(attempt.expired)
        self.assertFalse(attempt.process.stdout.closed, "timer must not close stdout mid-read")
        self.assert_blocked()
        proceed.set()
        self.assertTrue(attempt.done.wait(5))
        self.assertEqual(attempt.result["reason"], "expired")
        self.assertFalse(list(self.slot(attempt.account).glob(".exec-home-*")))
        self.assertFalse(self.manager.has_pending(self.home, "telegram", route("100"), "42"))
        self.assert_blocked()

    def test_close_waits_for_watcher_cleanup(self):
        import threading
        self.start()
        attempt = next(iter(self.manager._attempts.values()))
        entered, proceed = threading.Event(), threading.Event()
        original = self.manager._fetch_and_commit
        def delayed(attempt, code, root):
            entered.set()
            proceed.wait(3)
            return original(attempt, code, root)
        self.manager._fetch_and_commit = delayed
        import http.client
        from urllib.parse import urlsplit
        conn = http.client.HTTPConnection("127.0.0.1", urlsplit(attempt.redirect).port, timeout=3)
        conn.request("GET", "/?code=good")
        conn.getresponse().read()
        conn.close()
        self.assertTrue(entered.wait(3))
        closer = threading.Thread(target=self.manager.close)
        closer.start()
        proceed.set()
        closer.join(5)
        self.assertFalse(closer.is_alive())
        self.assertTrue(attempt.finished)
        self.assert_blocked()
        self.assertTrue(attempt.process.stdout.closed)
        self.assertFalse(self.manager._attempts)
        self.assertFalse(self.handles[0][0].active)

    def test_identity_mismatch_never_echoes_reported_identity(self):
        self.provision(self.home, "typo@example.com", "other@example.com")
        result = self.manager.start(self.home, "telegram", route("100"), "42", "typo@example.com", self.register)
        self.assertTrue(result["ok"])
        attempt = self.pending()
        response = self.manager.finish(self.home, "telegram", route("100"), "42", "typo@example.com",
                                       attempt.redirect + "?code=good")
        self.assertFalse(response["ok"])
        self.assertEqual(response["reason"], "identity_mismatch")
        self.assertNotIn("other@example.com", response["error"])
        self.assert_blocked("typo@example.com")

    def test_unknown_identity_is_reported_as_unconfirmed_not_mismatch(self):
        self.provision(self.home, user="(unknown)")
        result = self.start()
        response = self.finish_with(result)
        self.assertIn("identity_unconfirmed", response["text"])
        self.assertNotIn("code=", response["text"])
        self.assert_blocked()

    def test_native_status_not_login_stdout_is_identity_authority(self):
        self.fake.write_text(self.fake.read_text().replace('"account": os.environ.get("FAKE_ACCOUNT", "user@example.com")',
                                                        '"account": "untrusted@example.com"'))
        result = self.start()
        self.assertIn("authorized in this profile", self.finish_with(result)["text"])

    def test_failure_reasons_are_stable_and_secret_free(self):
        result = self.start()
        attempt = next(iter(self.manager._attempts.values()))
        response = self.manager.finish(self.home, "telegram", route("100"), "42", "user@example.com",
                                       attempt.redirect + "?code=bad")
        self.assertEqual(response["reason"], "gws_failed")
        self.assertNotIn("bad", response["error"].replace("rejected", ""))
        self.assertIn("could not be completed", response["error"])
        for reason in oauth._REASON_HINTS:
            self.assertIn(reason, oauth._failure_message(reason))


    # --- lifecycle: status / cancel / retry / logout / crash cleanup ---

    def pending(self):
        return next(iter(self.manager._attempts.values()))

    def test_status_is_bound_to_exact_session_and_account(self):
        self.start()
        attempt = self.pending()
        ok = self.manager.status(self.home, "telegram", route("100"), "42", "user@example.com")
        self.assertEqual(ok["state"], "waiting")
        self.assertNotIn("client_source", ok)
        self.assertNotIn("fake", json.dumps(ok), "status must not echo client IDs")
        for args, profile in ((("telegram", "100", "43", "user@example.com"), ""),
                              (("telegram", "101", "42", "user@example.com"), ""),
                              (("discord", "100", "42", "user@example.com"), ""),
                              (("telegram", "100", "42", "other@example.com"), ""),
                              (("telegram", "100", "42", "user@example.com"), "other")):
            self.assertEqual(self.manager.status(self.home, args[0], route(args[1]), *args[2:], profile=profile)["state"], "none")
            self.assertFalse(self.manager.cancel(self.home, args[0], route(args[1]), *args[2:], profile=profile)["ok"])
        self.assertTrue(self.slot(attempt.account).is_dir())
        self.browser_hits_loopback(attempt)
        done = self.manager.status(self.home, "telegram", route("100"), "42", "user@example.com")
        self.assertEqual(done["state"], "finished")
        self.assertTrue(done["ok"] and done["consumed"])
        after = self.manager.status(self.home, "telegram", route("100"), "42", "user@example.com")
        self.assertEqual(after, {"ok": True, "state": "none", "account_registered": True})

    def test_cancel_stops_process_and_keeps_existing_credentials(self):
        account = self.seed_account()
        self.start(reauthorize=True)
        attempt = self.pending()
        response = self.manager.cancel(self.home, "telegram", route("100"), "42", "user@example.com")
        self.assertEqual(response, {"ok": True, "cancelled": True, "account": "user@example.com", "committed": False})
        self.assertIsNotNone(attempt.process.poll())
        self.assertFalse(list(self.slot(attempt.account).glob(".exec-home-*")))
        self.assertFalse((self.home / ".pending").exists())
        self.assert_blocked()
        self.assertFalse(self.handles[0][0].active)
        self.assertEqual((account / "credentials.enc").read_text(), "old-credentials")
        self.assertTrue(self.start(reauthorize=True)["ok"], "cancel frees the slot for a retry")

    def test_cancel_during_exchange_prevents_late_commit(self):
        import threading
        self.start()
        attempt = self.pending()
        entered, proceed = threading.Event(), threading.Event()
        original = self.manager._fetch_and_commit
        def delayed(attempt, code, root):
            entered.set()
            proceed.wait(3)
            return original(attempt, code, root)
        self.manager._fetch_and_commit = delayed
        outcome = []
        worker = threading.Thread(target=lambda: outcome.append(self.manager.finish(
            self.home, "telegram", route("100"), "42", "user@example.com", attempt.redirect + "?code=good")))
        worker.start()
        self.assertTrue(entered.wait(3))
        self.assertTrue(self.manager.cancel(self.home, "telegram", route("100"), "42", "user@example.com")["ok"])
        proceed.set()
        worker.join(5)
        self.assertFalse(outcome[0]["ok"])
        self.assertEqual(outcome[0]["reason"], "cancelled")
        self.assert_blocked()
        self.assertFalse(list(self.slot(attempt.account).glob(".exec-home-*")))

    def test_cancel_after_native_write_during_identity_check_never_unblocks(self):
        import threading
        router = backend_module.R
        started = self.start()
        attempt = self.pending()
        entered, release = threading.Event(), threading.Event()
        def verify(*args, **kwargs):
            entered.set()
            self.assertTrue(release.wait(3))
            return {"ok": True}
        with mock.patch.object(router, "account_identity", side_effect=verify):
            result = []
            worker = threading.Thread(target=lambda: result.append(self.manager.finish(
                self.home, "telegram", route("100"), "42", attempt.account, attempt.redirect + "?code=good")))
            worker.start()
            try:
                self.assertTrue(started["ok"] and entered.wait(3))
                self.assertEqual((self.slot() / "credentials.enc").read_text(), "good")
                self.assertTrue(self.manager.cancel(self.home, "telegram", route("100"), "42", attempt.account)["ok"])
            finally:
                release.set()
                worker.join(5)
        self.assertEqual(result[0]["reason"], "cancelled")
        self.assert_blocked()

    def test_malformed_callback_keeps_attempt_for_retry(self):
        result = self.start()
        attempt = self.pending()
        for query in ("", "?state=x", "?code=", "?code=good&code=bad", "?code=a%20b", "?code=good#frag", "?=&&"):
            with self.subTest(query=query):
                response = self.manager.finish(self.home, "telegram", route("100"), "42", "user@example.com",
                                               attempt.redirect + query)
                self.assertFalse(response["ok"])
                self.assertTrue(response["retryable"])
                self.assertEqual(response["reason"], "invalid_callback")
                self.assertIsNone(attempt.process.poll(), "gws loopback must stay alive")
        hooked = asyncio.run(self.handles[0][1](event=self.event(attempt.redirect + "?state=x")))
        self.assertEqual(hooked["action"], "rewrite")
        self.assertIn("still pending", hooked["text"])
        response = self.finish_with(result, "good")
        self.assertIn("user@example.com", response["text"])
        self.assertTrue((self.home / "accounts" / "user@example.com" / "credentials.enc").is_file())

    def test_access_denied_cancels_with_stable_reason(self):
        account = self.seed_account()
        self.start(reauthorize=True)
        attempt = self.pending()
        response = self.manager.finish(self.home, "telegram", route("100"), "42", "user@example.com",
                                       attempt.redirect + "?error=access_denied")
        self.assertFalse(response["ok"])
        self.assertEqual(response["reason"], "access_denied")
        self.assertNotIn("retryable", response)
        self.assertFalse(self.manager._attempts)
        self.assertFalse(list(self.slot(attempt.account).glob(".exec-home-*")))
        self.assertEqual((account / "credentials.enc").read_text(), "old-credentials")
        other = self.manager.start(self.home, "telegram", route("100"), "42", "user@example.com", self.register, timeout=10, reauthorize=True)
        response = self.manager.finish(self.home, "telegram", route("100"), "42", "user@example.com",
                                       self.pending().redirect + "?error=server_error")
        self.assertEqual(response["reason"], "oauth_error")

    def test_repeat_login_after_local_completion_reports_registered_account(self):
        self.start(timeout=0.6)
        self.browser_hits_loopback(self.pending())
        from time import sleep
        sleep(1.0)  # one-shot outcome released at the deadline, nobody read it
        again = self.start()
        self.assertEqual(again["reason"], "account_exists")
        self.assertTrue(again["account_registered"])
        renewed = self.start(reauthorize=True)
        self.assertTrue(renewed["ok"])
        self.assertTrue(renewed["reauthorize"])
        self.assertIn("same machine", renewed["instructions"])
        self.assertIn("another device", renewed["instructions"])

    def test_native_client_failure_and_missing_executable_have_safe_errors(self):
        (self.slot() / "client_secret.json").write_text("leak-fixture")
        result = self.start()
        self.assertEqual(result["reason"], "launch_failed")
        self.assertNotIn("leak", json.dumps(result))
        self.fake = self.home / "no-such-gws"
        self.assertEqual(self.start()["reason"], "gws_not_found")

    def test_logout_cancels_owned_writer_other_writer_cannot_overlap(self):
        account = self.seed_account()
        self.start(reauthorize=True)
        local = self.pending()
        other = self.new_manager()
        self.addCleanup(other.close)
        other_login = other.start(self.home, "cli", route("s"), "local", account.name, None, reauthorize=True)
        self.assertEqual(other_login["reason"], "account_busy")
        result = self.manager.logout(self.home, "User@Example.com")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["cancelled_logins"], 1)
        self.assertIsNotNone(local.process.poll())
        self.assertFalse((account / "credentials.enc").exists())
        self.assertTrue(self.start()["ok"])
        self.assertFalse(self.manager.logout(self.home, "nope")["ok"])

    def test_unload_leaves_existing_legacy_stores_untouched(self):
        legacy = self.home / ".pending" / ("a" * 24)
        legacy.mkdir(parents=True)
        old = legacy / "credentials.enc"
        old.write_text("stale")
        self.assertTrue(self.start()["ok"])
        self.manager.close()
        self.assertEqual(self.start()["reason"], "companion_unavailable")
        self.assertEqual(old.read_text(), "stale")
        self.assert_blocked()

    def test_scope_metadata_is_requested_not_granted(self):
        scopes = ["openid", "https://www.googleapis.com/auth/drive.readonly"]
        result = self.start(scope_mode="custom", scopes=scopes)
        self.assertEqual((result["scope_mode"], result["requested_scopes"]), ("custom", scopes))
        self.assertNotIn("granted_scopes", result)
        status = self.manager.status(self.home, "telegram", route("100"), "42", "user@example.com")
        self.assertEqual(status["requested_scopes"], scopes)
        done = self.finish_with(result, "good")
        self.assertIn("authorized in this profile", done["text"])
        self.seed_account("full@example.com")
        full = self.manager.start(self.home, "telegram", route("100"), "42", "full@example.com", self.register, timeout=10, reauthorize=True)
        response = self.manager.finish(self.home, "telegram", route("100"), "42", "full@example.com",
                                       self.pending().redirect + "?code=good")
        self.assertEqual((full["scope_mode"], full["requested_scopes"]), ("full", []))
        self.assertIn("identity_mismatch", response["reason"])  # fake reports user@example.com

    def test_status_registered_requires_real_credential_slot(self):
        accounts = self.home / "accounts"
        (accounts / "empty@example.com").mkdir(parents=True)
        real = self.seed_account("real@example.com")
        (accounts / "link@example.com").symlink_to(real, target_is_directory=True)
        state = lambda a: self.manager.status(self.home, "telegram", route("100"), "42", a)["account_registered"]
        self.assertTrue(state("real@example.com"))
        self.assertFalse(state("empty@example.com"))
        self.assertFalse(state("link@example.com"))
        self.assertFalse(state("../x"))
        self.assertFalse(state(None))

if __name__ == "__main__":
    unittest.main()
