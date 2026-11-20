"""Local logout only: synthetic account slots, no Google calls."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from util import plugin, backend_module
from test_login import FAKE_GWS


def logout_account(root, account):
    binary = Path(root) / "fake-native-logout"
    binary.write_text(FAKE_GWS.replace("{python}", sys.executable))
    binary.chmod(0o700)
    backend = backend_module.AccountBackend(root, lambda: str(binary), lambda args: {
        "ok": True, "contract": "gws-account-lifecycle-v1", "account": account, "credentials_in_use": False})
    return backend.logout(account)


make_pre_tool_call_hook = plugin.make_pre_tool_call_hook


class LogoutTests(unittest.TestCase):
    def test_exact_slot_logged_out_and_repeat_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = root / "client_secret.json"
            client.write_text("synthetic-client")
            for account in ("a@example.com", "b@example.com"):
                slot = root / "accounts" / account
                slot.mkdir(parents=True)
                (slot / "credentials.enc").write_text("synthetic")
            result = logout_account(root, "a@example.com")
            self.assertEqual(result["state"], "logged_out")
            self.assertFalse(result["remote_revoked"])
            self.assertFalse((root / "accounts/a@example.com/credentials.enc").exists())
            self.assertTrue((root / "accounts/b@example.com/credentials.enc").is_file())
            self.assertEqual(client.read_text(), "synthetic-client")
            self.assertEqual(logout_account(root, "a@example.com")["state"], "logged_out")

    def test_empty_native_logout_preserves_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            slot = Path(tmp) / "accounts/a@example.com"
            slot.mkdir(parents=True)
            (slot / "client_secret.json").write_text("{}")
            self.assertEqual(logout_account(tmp, "a@example.com")["state"], "logged_out")
            self.assertTrue((slot / "client_secret.json").exists())

    def test_path_traversal_and_symlinks_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for bad in (None, "", ".", "..", "../a", "/a", "a\n"):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    logout_account(root, bad)
            outside = root / "outside"
            outside.mkdir()
            (outside / "keep").write_text("keep")
            base = root / "accounts"
            base.mkdir()
            (base / "a@example.com").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                logout_account(root, "a@example.com")
            self.assertTrue((outside / "keep").is_file())

    def test_logout_requires_native_approval_not_model_flag(self):
        hook = make_pre_tool_call_hook()
        result = hook(tool_name="gws_logout", args={"account": "a@example.com", "approved": True})
        self.assertEqual(result["action"], "approve")
        self.assertEqual(result["rule_key"], "gws:a@example.com:logout")


if __name__ == "__main__":
    unittest.main()
