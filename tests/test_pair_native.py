"""Real Hermes loader/contexts/registry; synthetic identities and no Google calls.

Run with HERMES_AGENT_SRC/PYTHONPATH pointing at the host and GWS_PUBLIC_SRC at
its companion checkout. All homes, config and fake credentials are disposable.
"""
import argparse
from contextlib import redirect_stdout
import importlib
import io
import json
import os
import shutil
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from util import ROOT, PUBLIC, route
import test_login as fixtures
from test_login import FAKE_GWS


class NativePairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Host logging is process-global: initialize it in the suite's scratch
        # HERMES_HOME, not in a per-test home removed while its queue still runs.
        from hermes_logging import setup_logging
        setup_logging()

    def setUp(self):
        from hermes_cli.plugins import PluginManager, PluginContext
        from hermes_cli.plugins_manifest import parse_manifest_file
        from hermes_constants import set_hermes_home_override, reset_hermes_home_override
        self.tmp = tempfile.TemporaryDirectory(prefix="native-pair-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.token = set_hermes_home_override(self.home)
        self.addCleanup(reset_hermes_home_override, self.token)
        self.binary = self.home / "off-path native"
        self.binary.write_text(FAKE_GWS.replace("{python}", sys.executable))
        self.binary.chmod(0o700)
        self.config = {"plugins": {"isolation": "in_process", "entries": {
            "gws-workspace": {"settings": {"gws_bin": str(self.binary)}},
            "gws-remote-auth": {"settings": {"gws_bin": "/must-not-be-used"}}}}}
        (self.home / "config.yaml").write_text(json.dumps(self.config))
        self.manager = PluginManager(scope_key=str(self.home))
        self.addCleanup(self.manager.unload)
        for directory in (PUBLIC, ROOT):
            manifest = parse_manifest_file(directory / "plugin.yaml", directory, "user", "")
            assert manifest is not None
            self.manager._load_plugin(manifest)
            loaded = self.manager._plugins[manifest.name]
            self.assertTrue(loaded.enabled, loaded.error)
        self.public = self.manager._plugins["gws-workspace"].module
        self.private = self.manager._plugins["gws-remote-auth"].module
        assert self.public is not None and self.private is not None
        self.public_name = self.public.__name__
        self.backend = self.public.native_accounts
        self.context = PluginContext(self.manager._plugins["gws-remote-auth"].manifest, self.manager)
        self.root = self.home / "gws-oauth"
        self.root.mkdir(exist_ok=True)
        self.slot = fixtures.LoginTests.provision(self.root)
        self.oauth = importlib.import_module(self.private.__name__ + ".oauth")
        self.companion = importlib.import_module(self.private.__name__ + ".companion")
        self.session()

    def session(self, *, actor="operator", session="physical", chat="", profile=None):
        from gateway.session_context import set_session_vars
        set_session_vars(platform="cli", user_id="operator", actor_id=actor,
                         chat_id=chat, thread_id="", profile=profile or self.context.profile_name, cron_session="",
                         session_id=session, session_key="bound-" + session)

    def call(self, name="gws_login", **args):
        return json.loads(self.context.dispatch_tool(name, {"account": "user@example.com", **args},
                                                     session_id="physical"))

    def callback(self, result):
        from urllib.parse import parse_qs, urlsplit
        return parse_qs(urlsplit(result["url"]).query)["redirect_uri"][0] + "?code=good"

    def test_registered_pair_binary_identity_status_and_native_logout(self):
        with patch.dict(os.environ, {"PATH": "", "GOOGLE_WORKSPACE_CLI_TOKEN": "foreign",
                                    "CLOUDSDK_CONFIG": "foreign", "GOOGLE_APPLICATION_CREDENTIALS": "foreign"}):
            started = self.call()
            self.assertTrue(started["ok"], started)
            self.assertEqual(self.call(action="status")["state"], "waiting")
            result = self.call(callback_url=self.callback(started))
            self.assertTrue(result["ok"], result)
            health = self.backend.status("user@example.com")
            self.assertTrue(health["ok"], health)
            logged_out = self.call("gws_logout")
            self.assertEqual(logged_out["state"], "logged_out", logged_out)
        self.assertFalse((self.root / "accounts/user@example.com/credentials.enc").exists())
        self.assertTrue((self.root / "accounts/user@example.com/client_secret.json").exists())
        approvals = self.manager.invoke_hook("pre_tool_call", tool_name="gws_logout", args={"account": "user@example.com"})
        self.assertTrue(any(a.get("action") == "approve" and a.get("rule_key") == "gws:user@example.com:logout"
                            for a in approvals), approvals)

    def test_installed_native_gws_generates_consent_then_cancels_without_exchange(self):
        binary = shutil.which("gws")
        self.assertIsNotNone(binary, "install the native gws test prerequisite")
        self.config["plugins"]["entries"]["gws-workspace"]["settings"]["gws_bin"] = binary
        (self.home / "config.yaml").write_text(json.dumps(self.config))
        (self.slot / "client_secret.json").write_text(json.dumps({"installed": {
            "client_id": "synthetic.apps.googleusercontent.com", "project_id": "fixture-project",
            "client_secret": "synthetic", "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"}}))
        with patch.dict(os.environ, {"PATH": "", "GOOGLE_WORKSPACE_CLI_TOKEN": "foreign"}):
            started = self.call(scope_mode="readonly")
            self.assertTrue(started["ok"], started.get("reason"))
            self.assertTrue(self.callback(started).startswith("http://localhost:"))
            self.assertTrue(self.call(action="cancel")["ok"])
            self.assertFalse(self.backend.registered(self.slot.name))
            self.assertFalse(list(self.slot.glob(".exec-home-*")))
            self.assertTrue(self.call("gws_logout")["ok"])

    def test_absent_incompatible_unloaded_companion_and_pending_cancel(self):
        self.assertIs(self.companion.resolve_backend(self.root), self.backend)
        started = self.call()
        self.assertTrue(started["ok"], started)
        for replacement in (None, object()):
            with patch.object(self.public, "native_accounts", replacement):
                with self.assertRaises(ValueError):
                    self.companion.resolve_backend(self.root)
                self.assertEqual(self.call(action="status")["state"], "waiting")
        with patch.object(self.backend, "contract", "gws-native-account-v999"):
            self.assertEqual(self.call()["reason"], "companion_unavailable")
            with patch.object(self.oauth.http.client, "HTTPConnection", side_effect=AssertionError("forwarded")):
                self.assertEqual(self.call(callback_url=self.callback(started))["reason"], "companion_unavailable")
        self.assertFalse(self.backend.registered("user@example.com"))
        self.assertTrue(self.call()["ok"])
        self.manager.unload("gws-workspace")
        self.assertFalse(self.backend.active)
        self.assertTrue(self.call(action="cancel")["ok"])
        self.assertEqual(self.call()["reason"], "companion_unavailable")
        self.assertEqual(self.call("gws_logout")["reason"], "companion_unavailable")
        self.assertEqual(self.call(action="status")["reason"], "companion_unavailable")

    def test_wrong_identity_blocks_api_worker_and_listing_and_watch_cleanup_refuses_changes(self):
        started = self.call()
        self.assertTrue(self.call(callback_url=self.callback(started))["ok"])
        slot = self.root / "accounts/user@example.com"
        client = slot / "client_secret.json"
        client.write_text('{"installed":{"client_id":"fixture","client_secret":"synthetic","test_identity":"wrong@example.com"}}')
        started = self.call(reauthorize=True)
        rejected = self.call(callback_url=self.callback(started))
        self.assertEqual(rejected["reason"], "identity_mismatch", rejected)
        self.assertFalse(self.backend.registered(slot.name))
        self.assertFalse(self.call("gws_accounts")["accounts"])
        with patch.object(self.oauth.subprocess, "run") as native:
            self.assertEqual(self.call("gws_api", args=["drive", "files", "list"])["error_code"], "identity_unconfirmed")
            worker = importlib.import_module(self.public_name + ".watch_worker").GwsClient(self.home)
            self.assertFalse(worker.call(slot.name, ["drive", "files", "list"])["ok"])
            native.assert_not_called()
        original = (slot / "credentials.enc").read_bytes()
        store = importlib.import_module(self.public_name + ".watch").WatchStore(self.home)
        store.add_watch({"watch_id": "pair-native", "service": "gmail", "account": "user@example.com",
            "profile": "default", "principal": "operator", "origin": {}, "mode": "new_session",
            "target": {}, "filters": {}, "instructions": "", "skills": [], "minutes": 1,
            "batch_seconds": 0, "stop_after_match": False, "created_at": 1,
            "not_before": 1, "expires_at": 2, "fingerprint": "pair-native"})
        for state, cleanup in (("active", "none"), ("matched", "done"), ("stopped", "pending")):
            store.update_watch("pair-native", state=state, cleanup_state=cleanup)
            self.assertEqual(self.call(reauthorize=True)["reason"], "credentials_in_use")
            self.assertEqual(self.call("gws_logout")["reason"], "credentials_in_use")
            self.assertEqual((slot / "credentials.enc").read_bytes(), original)

    def test_timeout_cancel_and_profile_principal_session_isolation(self):
        # The manager uses the actual resolver and registered public backend.
        manager = self.oauth.LoginManager(callback_root=lambda: self.root)
        self.addCleanup(manager.close)
        started = manager.start(self.root, "cli", route("s"), "operator", "user@example.com", None, timeout=0.3)
        self.assertTrue(started["ok"], started)
        attempt = next(iter(manager._attempts.values()))
        time.sleep(0.7)
        self.assertIsNotNone(attempt.process.poll())
        self.assertFalse(list(self.slot.glob(".exec-home-*")))
        started = self.call()
        self.assertTrue(started["ok"], started)
        from agent.delegation_context import delegated_child_context
        with delegated_child_context("rebound"):
            result = json.loads(self.context.dispatch_tool("gws_login", {"account": "user@example.com", "action": "cancel"},
                                                           session_id="rebound"))
            self.assertEqual(result["reason"], "no_session_identity")
        for kwargs in ({"actor": "other"}, {"session": "other"}, {"profile": "other"}):
            self.session(**kwargs)
            self.assertFalse(self.call(action="cancel")["ok"])
        self.session()
        self.assertTrue(self.call(action="cancel")["ok"])
        with self.assertRaises(ValueError):
            self.companion.resolve_backend(self.home / "other/gws-oauth")
        self.assertFalse(self.backend.registered("user@example.com"))

    def test_gateway_callback_uses_current_route_and_physical_session(self):
        from dataclasses import replace
        from gateway.config import GatewayConfig, Platform
        from gateway.platforms.event import MessageEvent
        from gateway.session import SessionSource, SessionStore
        from gateway.session_context import set_session_vars, clear_session_vars
        import asyncio

        store = SessionStore(self.home / "sessions", GatewayConfig())
        self.addCleanup(store.close_all_db_handles)
        source = SessionSource(Platform.TELEGRAM, "100", user_id="operator", chat_type="group", thread_id="10")
        entry = store.get_or_create_session(source)

        def start(entry):
            tokens = set_session_vars(platform=source.platform.value, chat_id=source.chat_id, actor_id=source.user_id,
                profile="", session_key=entry.session_key, session_id=entry.session_id)
            try:
                result = json.loads(self.context.dispatch_tool("gws_login", {"account": "user@example.com"},
                                                              session_id=entry.session_id))
                self.assertTrue(result["ok"], result)
                return self.callback(result)
            finally:
                clear_session_vars(tokens)

        def paste(src, url):
            replies = asyncio.run(self.manager.ainvoke_hook("pre_gateway_dispatch", session_store=store,
                event=MessageEvent(url, source=src, user_id=src.user_id)))
            return next(value["text"] for value in replies if value.get("action") == "rewrite")

        first = start(entry)
        self.assertIn("original session", paste(replace(source, thread_id="11"), first))
        next_entry = store.get_or_create_session(source, force_new=True)
        self.assertNotEqual(next_entry.session_id, entry.session_id)
        self.assertIn("original session", paste(source, first))
        self.assertFalse(self.backend.registered("user@example.com"))
        # Reset cannot consume or replace the still-active writer. Cancel from
        # its original bound session (or let its deadline expire) before retry.
        tokens = set_session_vars(platform="telegram", chat_id="100", actor_id="operator", profile="",
                                  session_key=entry.session_key, session_id=entry.session_id)
        try:
            self.assertTrue(json.loads(self.context.dispatch_tool("gws_login", {
                "account": "user@example.com", "action": "cancel"}, session_id=entry.session_id))["ok"])
        finally:
            clear_session_vars(tokens)
        second = start(next_entry)
        self.assertIn("authorized", paste(source, second))
        self.assertTrue(self.backend.status("user@example.com")["ok"])

    def test_real_namespaced_second_profile_and_local_cli_cannot_overlap_remote_writer(self):
        from hermes_cli.plugins import PluginManager
        from hermes_cli.plugins_manifest import parse_manifest_file
        from hermes_constants import set_hermes_home_override, reset_hermes_home_override
        other_home = self.home / "isolated-profile"
        other_home.mkdir()
        other = PluginManager(scope_key=str(other_home))
        self.addCleanup(other.unload)
        manifest = parse_manifest_file(PUBLIC / "plugin.yaml", PUBLIC, "user", "")
        assert manifest is not None
        other._load_plugin(manifest)
        loaded = other._plugins["gws-workspace"]
        self.assertTrue(loaded.enabled, loaded.error)
        assert loaded.module is not None
        self.assertNotEqual(loaded.module.__name__, self.public.__name__)
        self.assertIs(self.companion.resolve_backend(other_home / "gws-oauth"), loaded.module.native_accounts)
        started = self.call()
        self.assertTrue(started["ok"], started)
        token = set_hermes_home_override(other_home)
        try:
            self.assertEqual(self.call(action="cancel")["reason"], "profile_mismatch")
        finally:
            reset_hermes_home_override(token)
        # Drive the actual registered CLI; shorten only the bounded lock wait.
        from hermes_cli.main import _attach_plugin_cli_command
        descriptor = self.manager._cli_commands["gws"]
        parser = argparse.ArgumentParser()
        _attach_plugin_cli_command(parser.add_subparsers(), descriptor)
        args = parser.parse_args(["gws", "logout", "user@example.com"])
        lifecycle = importlib.import_module(self.public_name + ".account_lifecycle")
        with patch.object(lifecycle, "_LOCK_TIMEOUT", 0.05), redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as exit:
            args.func(args)
        self.assertEqual(exit.exception.code, 1)
        self.assertTrue(self.call(action="cancel")["ok"])
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as exit:
            args.func(args)
        self.assertEqual(exit.exception.code, 0)
        result = self.call(callback_url=self.callback(started))
        self.assertEqual(result["reason"], "no_pending", result)
        self.assertFalse(self.backend.registered(self.slot.name))


if __name__ == "__main__":
    unittest.main()
