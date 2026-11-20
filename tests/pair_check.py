"""Offline cross-plugin lifecycle check: python tests/pair_check.py --public PATH.

Uses real public registration/SQLite and private dispatch/logout/locks. Only the
watch's network-dependent inner operation is replaced; no live OAuth is tested.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
from unittest.mock import patch


def load(name, root):
    spec = importlib.util.spec_from_file_location(name, root / "__init__.py",
                                                submodule_search_locations=[str(root)])
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main(public_root):
    private_root = Path(__file__).resolve().parents[1]
    public = load("pair_public", public_root)
    load("pair_private", private_root)
    watch_tools = importlib.import_module("pair_public.watch_tools")
    WatchStore = importlib.import_module("pair_public.watch").WatchStore
    LoginManager = importlib.import_module("pair_private.oauth").LoginManager
    with patch.dict(os.environ, {"GWS_PUBLIC_SRC": str(public_root.resolve())}):
        from test_login import FAKE_GWS
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        root = home / "gws-oauth"
        account = "user@example.com"
        slot = root / "accounts" / account
        slot.mkdir(parents=True)
        credential = slot / "credentials.enc"
        credential.write_text("synthetic-not-a-token")
        binary = home / "fake-gws"
        binary.write_text(FAKE_GWS.replace("{python}", sys.executable))
        binary.chmod(0o700)
        tools = {}
        ctx = SimpleNamespace(profile_name="default",
            get_config=lambda key, default=None: str(binary) if key == "gws_bin" else default,
            register_skill=lambda *a: None,
            register_cli_command=lambda *a, **kw: None,
            register_tool=lambda **kw: tools.setdefault(kw["name"], kw),
            register_hook=lambda *a, **kw: None,
            register_command=lambda *a, **kw: None,
            on_unload=lambda cb: None)
        with patch("hermes_constants.get_hermes_home", return_value=home):
            public.register(ctx)
            assert "gws_login" not in tools and "gws_logout" not in tools
            store = WatchStore(home)
            manager = LoginManager(backend=lambda r: public.native_accounts)
            backend = public.native_accounts
            def logout():
                return manager.logout(root, "USER@example.com")
            def add_watch():
                store.add_watch({"watch_id": "pair", "service": "gmail", "account": account,
                    "profile": "default", "principal": "u", "origin": {}, "mode": "new_session",
                    "target": {}, "filters": {}, "instructions": "", "skills": [], "minutes": 1,
                    "batch_seconds": 0, "stop_after_match": False, "created_at": 1,
                    "not_before": 1, "expires_at": 2, "fingerprint": "pair"})
            add_watch()
            for state, cleanup in (("active", "none"), ("matched", "done"), ("stopped", "pending")):
                store.update_watch("pair", state=state, cleanup_state=cleanup)
                assert logout()["reason"] == "credentials_in_use", (state, cleanup)
                assert credential.read_text() == "synthetic-not-a-token"
            store.update_watch("pair", state="stopped", cleanup_state="done")
            assert logout()["ok"] is True and not credential.exists()
            credential.write_text("synthetic-not-a-token")
            runtime = SimpleNamespace(store=store)
            args = {"action": "start", "account": "USER@example.com", "delivery_mode": "new_session"}

            # Real public barrier is held until reservation; private logout must
            # wait and then observe the reservation through actual public dispatch.
            entered, release, attempted = threading.Event(), threading.Event(), threading.Event()
            def reserve(*a, **kw):
                entered.set()
                assert release.wait(5), "Watch test timed out"
                store.update_watch("pair", state="active", cleanup_state="none")
                return {"ok": True}
            def attempted_logout():
                attempted.set()
                return logout()
            with patch.object(watch_tools, "_handle", side_effect=reserve), ThreadPoolExecutor(2) as pool:
                start = pool.submit(watch_tools.handle, "gmail", args, runtime)
                try:
                    assert entered.wait(5)
                    removal = pool.submit(attempted_logout)
                    assert attempted.wait(5)
                    assert not removal.done() and credential.exists()
                finally:
                    release.set()
                assert start.result(timeout=5)["ok"]
                assert removal.result(timeout=5)["reason"] == "credentials_in_use"

            # Reverse order: public start cannot enter its inner operation before
            # private logout finishes. Both paths use the public lock implementation.
            store.update_watch("pair", state="stopped", cleanup_state="done")
            entered.clear(); release.clear(); attempted.clear()
            router = importlib.import_module("pair_public.router")
            original_run = router._run_gws
            def remove(*a, **kw):
                entered.set()
                assert release.wait(5), "Logout test timed out"
                return original_run(*a, **kw)
            def after_removal(*a, **kw):
                assert not credential.exists(), "Watch bypassed the lifecycle fence"
                return {"ok": True}
            def attempted_start():
                attempted.set()
                return watch_tools.handle("gmail", args, runtime)
            with patch.object(watch_tools, "_handle", side_effect=after_removal), patch.object(router, "_run_gws", remove), ThreadPoolExecutor(2) as pool:
                removal = pool.submit(manager.logout, root, account)
                try:
                    assert entered.wait(5)
                    start = pool.submit(attempted_start)
                    assert attempted.wait(5)
                    assert not start.done()
                finally:
                    release.set()
                assert removal.result(timeout=5)["ok"]
                assert start.result(timeout=5)["ok"]
            manager.close()
    print("PASS: public/private shared lifecycle, busy/cleanup refusal, both race orderings")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", required=True, type=Path)
    main(parser.parse_args().public.resolve())
