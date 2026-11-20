"""Load this private package in place, without installing it."""
import importlib.util
import importlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gws_remote_auth_test", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
assert spec is not None and spec.loader is not None
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)

# Import the actual public checkout; never maintain a second backend in fixtures.
PUBLIC = Path(os.environ.get("GWS_PUBLIC_SRC", ROOT.parent / "hermes-google-workspace-split"))
public_spec = importlib.util.spec_from_file_location("gws_shared_test", PUBLIC / "__init__.py",
                                                  submodule_search_locations=[str(PUBLIC)])
assert public_spec is not None and public_spec.loader is not None
public = importlib.util.module_from_spec(public_spec)
sys.modules[public_spec.name] = public
public_spec.loader.exec_module(public)
backend_module = importlib.import_module(public.__name__ + ".account_backend")
oauth = importlib.import_module(plugin.__name__ + ".oauth")


def route(chat):
    return (chat, "route-" + chat, "session-" + chat)
