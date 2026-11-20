"""Private boundary and lifecycle checks; synthetic stores and loopback only."""
import asyncio
import importlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from contextvars import ContextVar
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock

from util import plugin, PUBLIC, public, backend_module, route
import test_login as fixtures

oauth = importlib.import_module(plugin.__name__ + ".oauth")
lifecycle = importlib.import_module(public.__name__ + ".account_lifecycle")


def response(account="user@example.com", busy=False):
    return json.dumps({"ok": True, "contract": "gws-account-lifecycle-v1",
                       "account": account, "credentials_in_use": busy})


class ContractTests(unittest.TestCase):
    def test_backend_rejects_malformed_or_unavailable_lifecycle(self):
        account = "user@example.com"
        good = json.loads(response())
        with tempfile.TemporaryDirectory() as tmp:
            check = mock.Mock(return_value=good)
            backend = backend_module.AccountBackend(tmp, lambda: "gws", check)
            def check_guard():
                with backend._guard(account):
                    pass
            check_guard()
            check.assert_called_once_with({"account": account, "check_lifecycle": True})
            for value in (None, {}, response(), [], dict(good, ok=1), dict(good, account="wrong"),
                          dict(good, contract="v2"), dict(good, credentials_in_use=0)):
                check.return_value = value
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, "^companion_unavailable$"):
                    check_guard()
            check.side_effect = RuntimeError("fixture secret must not leak")
            with self.assertRaisesRegex(ValueError, "^companion_unavailable$"):
                check_guard()

    def test_busy_response_is_not_a_compatible_permission(self):
        with self.assertRaisesRegex(ValueError, "^credentials_in_use$"):
            backend_module.check_lifecycle(json.loads(response(busy=True)), "user@example.com")

    def test_manager_without_probe_never_launches(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(oauth.subprocess, "Popen") as spawn:
            manager = oauth.LoginManager()
            result = manager.start(tmp, "cli", route("s"), "actor", "user@example.com", None)
            self.assertEqual(result["reason"], "companion_unavailable")
            spawn.assert_not_called()

    def test_lifecycle_barrier_is_cross_process_and_account_specific(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "probe.py"
            script.write_text("import sys\nsys.path.insert(0, sys.argv[1])\n"
                              "from account_lifecycle import lifecycle_guard\n"
                              "with lifecycle_guard(sys.argv[2], sys.argv[3]):\n"
                              "    print('acquired', flush=True)\n")
            with lifecycle.lifecycle_guard(tmp, "user@example.com"):
                other = subprocess.run([sys.executable, "-S", str(script), str(PUBLIC), tmp, "other@example.com"],
                                       capture_output=True, text=True, timeout=3)
                self.assertEqual(other.stdout.strip(), "acquired")
                child = subprocess.Popen([sys.executable, "-S", str(script), str(PUBLIC), tmp, "user@example.com"],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        child.wait(timeout=0.15)
                except BaseException:
                    child.kill()
                    child.communicate()
                    raise
            out, err = child.communicate(timeout=3)
            self.assertEqual((child.returncode, out.strip(), err), (0, "acquired", ""))


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.flow = fixtures.LoginTests()
        self.flow.setUp()
        self.addCleanup(self.flow.doCleanups)

    def test_watch_cannot_enter_lifecycle_while_native_consent_is_pending(self):
        f = self.flow
        slot = f.seed_account()
        self.assertTrue(f.start(reauthorize=True)["ok"])
        with self.assertRaises(TimeoutError):
            with lifecycle.lifecycle_guard(f.home, slot.name, wait=False):
                self.fail("watch entered while native consent was active")
        result = f.manager.finish(f.home, "telegram", route("100"), "42", slot.name, f.pending().redirect + "?code=good")
        self.assertTrue(result["ok"], result)
        with lifecycle.lifecycle_guard(f.home, slot.name, wait=False):
            self.assertTrue(f.backends[f.home].registered(slot.name))

    def test_active_watch_refuses_before_native_mutation(self):
        f = self.flow
        slot = f.seed_account()
        def deny(root, account):
            raise backend_module.AccountError("credentials_in_use")
        f.check_lifecycle = deny
        with mock.patch.object(oauth.subprocess, "Popen") as native:
            self.assertEqual(f.start(reauthorize=True)["reason"], "credentials_in_use")
            self.assertEqual(f.manager.logout(f.home, slot.name)["reason"], "credentials_in_use")
            native.assert_not_called()
        self.assertTrue(f.backends[f.home].registered(slot.name))

    def test_callback_root_and_cleared_actor_are_strict(self):
        f = self.flow
        f.start()
        url = f.pending().redirect + "?code=good"
        event = f.event(url)
        event.user_id = ""  # source.user_id still contains the route owner
        self.assertIsNone(asyncio.run(f.manager.on_message(event)))
        event.user_id = "other"
        self.assertIsNone(asyncio.run(f.manager.on_message(event)))
        f.manager._callback_root = lambda: f.home / "other-profile"
        self.assertIsNone(asyncio.run(f.manager.on_message(f.event(url))))
        self.assertIsNone(f.pending().process.poll())

    def test_logout_drains_existing_native_account_locks(self):
        f = self.flow
        slot = f.seed_account()
        router = importlib.import_module(public.__name__ + ".router")
        completed = threading.Event()
        outcome = []
        def logout():
            outcome.append(f.manager.logout(f.home, "user@example.com"))
            completed.set()
        with router._native_guard(f.home, "user@example.com"):
            worker = threading.Thread(target=logout)
            worker.start()
            self.assertFalse(completed.wait(0.15))
            self.assertFalse((slot / ".hermes-unverified").exists())
            self.assertTrue(slot.exists())
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertTrue(outcome[0]["ok"])
        self.assertFalse((slot / "credentials.enc").exists())


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.current_home = ContextVar("private_test_home", default=self.home)
        self.session = {"HERMES_SESSION_PLATFORM": "telegram", "HERMES_SESSION_CHAT_ID": "100",
                        "HERMES_SESSION_ACTOR_ID": "42", "HERMES_SESSION_USER_ID": "stale-route-user",
                        "HERMES_SESSION_PROFILE": "default", "HERMES_SESSION_ID": "session-1"}
        self.bound = True
        constants = ModuleType("hermes_constants")
        setattr(constants, "get_hermes_home", self.current_home.get)
        setattr(constants, "set_hermes_home_override", self.current_home.set)
        setattr(constants, "reset_hermes_home_override", self.current_home.reset)
        gateway = ModuleType("gateway")
        gateway.__path__ = []
        context = ModuleType("gateway.session_context")
        setattr(context, "_bound_session_value", lambda key: self.session.get(key) if self.bound else None)
        self.session["HERMES_SESSION_KEY"] = "bound"
        self.tools, self.hooks, self.unload, self.calls = {}, [], [], []
        self.busy = False
        self.fake = self.home / "fake-gws"
        self.fake.write_text(fixtures.FAKE_GWS.replace("{python}", sys.executable))
        self.fake.chmod(0o700)
        self.config = {"gws_bin": str(self.fake)}
        def dispatch(name, args):
            self.calls.append((name, args, self.current_home.get()))
            return response(args["account"], self.busy)
        def hook(name, callback):
            handle = SimpleNamespace(active=True)
            handle.dispose = lambda: setattr(handle, "active", False)
            self.hooks.append((name, callback, handle))
            return handle
        self.ctx = SimpleNamespace(profile_name="default", dispatch_tool=dispatch,
            register_skill=lambda *args: None,
            get_config=lambda key, default=None: self.config.get(key, default),
            register_tool=lambda **kw: self.tools.setdefault(kw["name"], kw),
            register_hook=hook, on_unload=self.unload.append)
        with mock.patch.dict(sys.modules, {"hermes_constants": constants, "gateway": gateway,
                                          "gateway.session_context": context}):
            plugin.register(self.ctx)
        self.addCleanup(self.unload[0])
        self.root = self.home / "gws-oauth"
        self.root.mkdir(mode=0o700)
        backend = backend_module.AccountBackend(self.root, lambda: self.config["gws_bin"],
            lambda args: json.loads(dispatch("gws_accounts", args)))
        namespace = mock.patch.dict(sys.modules, {"hermes_plugins.google_workspace": SimpleNamespace(native_accounts=backend)})
        namespace.start()
        self.addCleanup(namespace.stop)
        fixtures.LoginTests.provision(self.root)

    def call(self, name="gws_login", **args):
        return json.loads(self.tools[name]["handler"]({"account": "user@example.com", **args}, session_id="session-1"))

    def test_registration_exact_tools_runtime_config_and_origin(self):
        self.assertEqual(set(self.tools), {"gws_login", "gws_logout"})
        self.assertEqual([h[0] for h in self.hooks], ["pre_tool_call"])
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.bound = False
        self.assertEqual(self.call()["reason"], "no_session_identity")
        self.bound = True
        self.session["HERMES_SESSION_ACTOR_ID"] = ""
        self.assertEqual(self.call()["reason"], "no_session_identity")
        self.assertEqual(self.call("gws_logout")["reason"], "no_session_identity")
        self.session["HERMES_SESSION_ACTOR_ID"] = "42"
        token = self.current_home.set(self.home / "wrong")
        self.assertEqual(self.call()["reason"], "profile_mismatch")
        self.current_home.reset(token)
        self.config["gws_bin"] = str(self.home / "missing")
        self.assertEqual(self.call()["reason"], "gws_not_found")
        self.config["gws_bin"] = str(self.fake)
        self.assertTrue(self.call()["ok"])
        self.assertEqual(self.call(action="status")["state"], "waiting")
        self.assertTrue(self.call(action="cancel")["ok"])

    def test_registered_flow_holds_lifecycle_during_consent_and_rechecks_on_logout(self):
        self.assertTrue(self.call()["ok"])
        callback = next(h[1] for h in self.hooks if h[0] == "pre_gateway_dispatch")
        manager = callback.__self__
        attempt = next(iter(manager._attempts.values()))
        import http.client
        from urllib.parse import urlsplit
        conn = http.client.HTTPConnection("127.0.0.1", urlsplit(attempt.redirect).port, timeout=3)
        conn.request("GET", "/?code=good")
        conn.getresponse().read()
        conn.close()
        self.assertTrue(attempt.done.wait(5))
        self.assertTrue(self.call(action="status")["ok"])
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(all(c[2] == self.home for c in self.calls))
        slot = self.root / "accounts/user@example.com"
        self.busy = True
        self.assertEqual(self.call("gws_logout")["reason"], "credentials_in_use")
        self.assertTrue(slot.exists())
        self.busy = False
        result = self.call("gws_logout", account="User@Example.com")
        self.assertEqual(result["state"], "logged_out")
        self.assertFalse((slot / "credentials.enc").exists())
        self.assertFalse(result["remote_revoked"])
        self.assertEqual(self.calls[-1][1], {"account": "user@example.com", "check_lifecycle": True})


if __name__ == "__main__":
    unittest.main()
