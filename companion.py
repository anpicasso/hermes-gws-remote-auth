"""Resolve only an already registered, same-profile public native backend."""
import re
import sys
from pathlib import Path

_NAMESPACE = re.compile(r"hermes_plugins\.gws_workspace(?:__home_[0-9a-f]{12})?\Z")


def resolve_backend(root):
    # Hermes imports directory plugins into profile-specific namespaces. Do not
    # import by filesystem path: that would duplicate state and bypass unloading.
    matches = []
    for name, module in list(sys.modules.items()):
        if not _NAMESPACE.fullmatch(name):
            continue
        backend = getattr(module, "native_accounts", None)
        if (getattr(backend, "contract", None) == "gws-native-account-v2"
                and getattr(backend, "active", False) is True
                and getattr(backend, "root", None) == Path(root).absolute()
                and all(callable(getattr(backend, method, None)) for method in
                        ("registered", "auth_process", "logout"))):
            matches.append(backend)
    if len(matches) != 1:
        raise ValueError("companion_unavailable")
    return matches[0]
