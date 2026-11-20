"""Supervise one native login per bound profile, actor and conversation.

The gateway hook is leased only while a child waits on its loopback callback.
Explicit callbacks pass through the model; neither path puts codes in CLI argv.

Two completion paths exist:
- Remote browser: the redirect to ``http://localhost:<port>`` fails in the
  user's browser; the user pastes that URL and the plugin forwards only the
  code to the live ``gws`` loopback server.
- Local browser (same host as Hermes): the redirect reaches the ``gws``
  loopback directly, ``gws`` exchanges the code and exits by itself. A watcher
  thread verifies the saved identity; a later paste of the same URL is
  still intercepted and answered with the stored outcome.
"""
from __future__ import annotations

import asyncio
from contextlib import ExitStack, contextmanager
import http.client
import os
import re
import select
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from .companion import resolve_backend

_EMAIL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+%-]*@[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}\Z")
_URL = re.compile(r"https://accounts\.google\.com/[^\s]+")
_CODE = re.compile(r"[A-Za-z0-9_./~-]{1,2048}")


def _login_flags(scope_mode, scopes):
    if scope_mode not in {"default", "readonly", "full", "custom"}:
        raise ValueError("scope_mode must be default, readonly, full or custom")
    if scopes is None:
        scopes = []
    if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
        raise ValueError("scopes must be a list of strings")
    if scope_mode != "custom" and scopes:
        raise ValueError("scopes is only used with scope_mode=custom")
    if scope_mode == "custom" and (not scopes or len(scopes) > 100 or any(
            not scope or len(scope) > 512 or "," in scope or any(char.isspace() for char in scope)
            for scope in scopes)):
        raise ValueError("invalid custom scopes")
    command = []
    if scope_mode in {"readonly", "full"}:
        command.append("--" + scope_mode)
    elif scope_mode == "custom":
        command.extend(("--scopes", ",".join(scopes)))
    return command


class LoginError(RuntimeError):
    """Login failure with a stable, secret-free reason code and an optional safe detail."""

    def __init__(self, reason, message="", *, detail=""):
        super().__init__(message or reason)
        self.reason = reason
        self.detail = detail


_REASON_HINTS = {
    "unsupported_lock_backend": "managed native auth requires POSIX process locks",
    "companion_unavailable": "enable a compatible gws-workspace plugin in this profile",
    "credentials_in_use": "stop account watches and finish cleanup before changing credentials",
    "invalid_callback": "the pasted URL is not this login's localhost callback",
    "expired": "the login deadline passed",
    "callback_rejected": "gws did not accept the local callback",
    "gws_failed": "native gws login did not complete",
    "launch_failed": "run hermes gws setup EMAIL locally for this account and check the native binary",
    "gws_not_found": "install gws on PATH or set plugins.entries.gws-workspace.settings.gws_bin",
    "account_busy": "finish or cancel the other account operation, then retry",
    "logout_required": "existing native token cache or plaintext fallback; explicitly log out before replacing it",
    "identity_unconfirmed": "gws could not read the authorized account's email (userinfo)",
    "identity_mismatch": "the authorized Google account is not the requested one; check the exact email spelling",
    "account_exists": "native credentials already exist; use reauthorize=true",
    "verification_failed": "the native account could not be verified for routing",
    "cancelled": "the login was cancelled (gws_login cancel or account logout)",
    "access_denied": "Google consent was denied or cancelled in the browser",
    "oauth_error": "Google returned an OAuth error in the callback",
}


def _failure_message(reason, detail=""):
    hint = _REASON_HINTS.get(reason, "internal error")
    extra = f"; {detail}" if detail else ""
    return f"the login could not be completed ({reason}: {hint}{extra}). Start a new login; do not reuse the link."


@dataclass
class _Attempt:
    process: subprocess.Popen
    redirect: str
    account: str
    deadline: float
    backend: object
    resources: ExitStack
    verify: Callable
    reauthorize: bool = False
    scope_mode: str = "full"
    requested_scopes: list = field(default_factory=list)
    cancelled: bool = False
    committed: bool = False
    timer: threading.Timer | None = None
    watcher: threading.Thread | None = None
    processing: bool = False
    expired: bool = False
    finished: bool = False
    result: dict | None = None
    done: threading.Event = field(default_factory=threading.Event)
    lock: threading.RLock = field(default_factory=threading.RLock)

    def scope_info(self):
        # What was *requested*; Google may grant less. Granted scopes come from the account itself.
        return {"scope_mode": self.scope_mode, "requested_scopes": list(self.requested_scopes)}


class LoginManager:
    def __init__(self, *, backend=resolve_backend, callback_root=None):
        self._lock = threading.RLock()
        self._attempts: dict[tuple, _Attempt] = {}
        self._hook = None
        self._closed = False
        self._backend = backend
        self._callback_root = callback_root

    @staticmethod
    def _key(root, platform, route, user_id, profile=""):
        # Chat alone survives a reset and may span several topics. Include the
        # host's logical route AND its current physical conversation.
        chat, logical, physical = route
        if not logical or not physical:
            raise ValueError("no_session_identity")
        return (str(Path(root).resolve()), str(platform), str(chat), str(user_id), str(profile or ""), logical, physical)

    def has_pending(self, root, platform, route, user_id):
        with self._lock:
            return self._key(root, platform, route, user_id) in self._attempts

    @staticmethod
    def _authorization_url(proc, timeout: float = 25):
        end = time.monotonic() + timeout
        data = bytearray()
        while time.monotonic() < end and len(data) < 16384:
            if proc.poll() is not None:
                break
            ready, _, _ = select.select([proc.stdout], [], [], min(0.2, end - time.monotonic()))
            if ready:
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk:
                    break
                data.extend(chunk)
                decoded = data.decode("utf-8", "replace")
                if match := _URL.search(decoded):
                    if match.end() < len(decoded) and decoded[match.end()].isspace():
                        return match.group(0).rstrip(".,)")
        raise RuntimeError("gws did not print an OAuth URL")

    def start(self, root, platform, route, user_id, account, register_hook, *,
              timeout: float = 300, profile="", scope_mode="full", scopes=None,
              reauthorize=False):
        root = Path(root).expanduser().absolute()
        if not isinstance(reauthorize, bool):
            return {"ok": False, "reason": "invalid_arguments", "error": "reauthorize must be a boolean."}
        key = self._key(root, platform, route, user_id, profile)
        if not platform or not user_id:
            return {"ok": False, "reason": "no_session_identity", "error": "This session needs a stable identity to complete OAuth."}
        if not _EMAIL.fullmatch(account or ""):
            return {"ok": False, "reason": "invalid_arguments", "error": "Give the exact Google account email."}
        if not 0 < timeout <= 900:
            return {"ok": False, "reason": "invalid_arguments", "error": "Invalid OAuth timeout."}
        account = account.lower()
        try:
            backend = self._backend(root)
        except (OSError, ValueError) as exc:
            reason = getattr(exc, "reason", "companion_unavailable")
            return {"ok": False, "reason": reason, "error": _failure_message(reason)}
        with self._lock:
            existing = self._attempts.get(key)
            if existing is not None:
                with existing.lock:
                    finished, stored = existing.finished, existing.result
                if finished:
                    # Outcome of a login that gws completed by itself (local browser)
                    # or that failed without a paste: hand it over exactly once.
                    self._remove(key, existing)
                    if existing.account == account.lower() and stored is not None:
                        return dict(stored, consumed=True)
                else:
                    return {"ok": False, "pending": True, "reason": "pending", "account": existing.account,
                            "error": "A login is already pending in this session. If the browser already showed "
                                     "'Success', check gws_login status with the same account; otherwise paste the "
                                     "localhost URL, or cancel it with gws_login cancel."}
        try:
            flags = _login_flags(scope_mode, scopes)
        except ValueError as exc:
            return {"ok": False, "reason": "invalid_arguments", "error": str(exc)}
        with self._lock:
            if self._closed:
                return {"ok": False, "reason": "companion_unavailable", "error": "Remote login is unloaded."}
            if key in self._attempts:
                return {"ok": False, "pending": True, "reason": "pending", "error": "A login is already pending in this session."}
            resources = ExitStack()
            deadline = time.monotonic() + timeout
            try:
                command, options, verify = resources.enter_context(
                    backend.auth_process(account, "login", flags, replace=reauthorize))
                proc = subprocess.Popen(command, **options, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
                url = self._authorization_url(proc, timeout=min(25, max(0, deadline - time.monotonic())))
                redirect = parse_qs(urlsplit(url).query).get("redirect_uri", [""])[0]
                parsed = urlsplit(redirect)
                if parsed.scheme != "http" or parsed.hostname != "localhost" or not parsed.port or parsed.path not in ("", "/"):
                    raise ValueError("gws returned an unexpected redirect")
                attempt = _Attempt(
                    proc, redirect, account, deadline, backend, resources, verify, reauthorize=reauthorize,
                    scope_mode=scope_mode, requested_scopes=list(scopes or []),
                )
                self._attempts[key] = attempt
                if register_hook is not None and (self._hook is None or not self._hook.active):
                    self._hook = register_hook(self.on_message)
                timer = threading.Timer(max(0, deadline - time.monotonic()), self._expire, args=(key, attempt))
                timer.daemon = True
                attempt.timer = timer
                timer.start()
                watcher = threading.Thread(target=self._watch_process, args=(key, attempt), daemon=True)
                attempt.watcher = watcher
                watcher.start()
                return {"ok": True, "url": url, "account": account.lower(), "timeout_seconds": timeout,
                        "reauthorize": reauthorize, **attempt.scope_info(),
                        "instructions": (
                            f"Open the link and sign in as {account.lower()}, then accept the permissions. "
                            "Browser on the same machine as Hermes: the page shows 'Success' and the account is "
                            "saved automatically; confirm with gws_login status (same account) or gws_accounts. "
                            "Browser on another device: it ends on a 'localhost' connection error page. That is "
                            "expected; copy the full localhost URL from the address bar and paste it in this same "
                            "chat (or pass it as callback_url). A mistyped URL can be pasted again; cancel with "
                            "gws_login cancel."
                        )}
            except (OSError, ValueError, RuntimeError, TypeError) as exc:
                self._attempts.pop(key, None)
                if not self._attempts and self._hook is not None:
                    self._hook.dispose()
                    self._hook = None
                if "proc" in locals():
                    self._terminate(proc)
                resources.close()
                reason = getattr(exc, "reason", "gws_not_found" if isinstance(exc, FileNotFoundError)
                                 else "account_busy" if isinstance(exc, TimeoutError) else "launch_failed")
                return {"ok": False, "reason": reason, "error": _failure_message(reason),
                        **({"account_registered": backend.registered(account)} if reason == "account_exists" else {})}

    @staticmethod
    def _terminate(proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        if proc.stdout is not None:
            proc.stdout.close()

    @staticmethod
    def _release(attempt):
        with attempt.lock:
            attempt.resources.close()

    def _remove(self, key, attempt):
        with self._lock:
            if self._attempts.get(key) is not attempt:
                return
            self._attempts.pop(key)
            if attempt.timer:
                attempt.timer.cancel()
            if not self._attempts and self._hook is not None:
                self._hook.dispose()
                self._hook = None

    def _expire(self, key, attempt, *, finished=False):
        """Deadline/unload/completion cleanup; an exchange in flight owns its own cleanup."""
        with attempt.lock:
            attempt.expired = True
            in_flight = attempt.processing and not attempt.finished and not finished
        if in_flight and attempt.process.poll() is not None:
            # The exchange thread is reading the output of a process that already
            # exited (local browser); closing its stdout here would corrupt that read.
            return
        self._terminate(attempt.process)
        if in_flight:
            return
        self._remove(key, attempt)
        self._release(attempt)

    def close(self):
        """Plugin unload: stop every attempt and wait briefly for owners to finish cleanup."""
        with self._lock:
            self._closed = True
            pending = list(self._attempts.items())
        for key, attempt in pending:
            self._expire(key, attempt)
            self._remove(key, attempt)
        # An exchange thread may still be reading an exited process; give it a
        # bounded chance to finish (verify or release the account lock) without holding locks.
        for _, attempt in pending:
            if attempt.watcher is not None and attempt.watcher is not threading.current_thread():
                attempt.watcher.join(3)
            if attempt.processing and not attempt.finished:
                attempt.done.wait(3)
            if attempt.process.stdout is not None and not attempt.process.stdout.closed and attempt.finished:
                attempt.process.stdout.close()
            if attempt.finished:
                self._release(attempt)

    def _watch_process(self, key, attempt):
        """Commit a login that gws completed by itself (browser on the Hermes host)."""
        try:
            attempt.process.wait()
        except Exception:
            return
        with attempt.lock:
            if attempt.expired or attempt.processing or attempt.finished:
                return  # terminated by the plugin, or a pasted callback drives the exchange
            attempt.processing = True
        result = self._run_exchange(key, attempt, None, local=True)
        self._release(attempt)
        with attempt.lock:
            attempt.result = result
            attempt.finished = True
            attempt.done.set()
            expired = attempt.expired
        if expired:
            self._remove(key, attempt)
        # Otherwise stay registered until the deadline, a pasted callback or a
        # gws_login status call hands the stored outcome over exactly once.

    def _fetch_and_commit(self, attempt, code, root):
        """Forward the code (if the loopback is still up), then verify the native identity."""
        if self._backend(root) is not attempt.backend:
            raise LoginError("companion_unavailable")
        process = attempt.process
        if code is not None and process.poll() is None:
            port = urlsplit(attempt.redirect).port
            status = None
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                try:
                    conn.request("GET", "/?code=" + code)
                    response = conn.getresponse()
                    response.read()
                    status = response.status
                finally:
                    conn.close()
            except OSError:
                status = None
            if status != 200:
                # The loopback may be gone because the browser already reached it;
                # accept that only if gws then finishes on its own.
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    raise LoginError("callback_rejected") from None
        remaining = max(0.1, attempt.deadline - time.monotonic())
        try:
            process.communicate(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise LoginError("expired") from None
        if process.returncode != 0:
            raise LoginError("gws_failed")
        # Keep the shared writer fence until the stored identity is confirmed.
        backend = self._backend(root)
        if backend is not attempt.backend:
            raise LoginError("companion_unavailable")

        def validate():
            if attempt.cancelled:
                raise LoginError("cancelled")
            if attempt.expired or time.monotonic() >= attempt.deadline:
                raise LoginError("expired")

        @contextmanager
        def commit_guard():
            # Cancel remains available during native identity lookup and while
            # identity is being confirmed. Only unblocking this account competes with cancellation.
            with attempt.lock:
                validate()
                yield
                attempt.committed = True

        validate()
        try:
            attempt.verify(guard=commit_guard, timeout=min(20, max(0, attempt.deadline - time.monotonic())))
        except (OSError, ValueError) as exc:
            validate()  # Report expiry/cancellation rather than its native side effect.
            raise LoginError(getattr(exc, "reason", "verification_failed")) from None
        return attempt.account

    def _run_exchange(self, key, attempt, code, *, local=False):
        """Run the exchange for one attempt; never raises, never echoes the code."""
        try:
            if time.monotonic() >= attempt.deadline:
                raise LoginError("expired")
            account = self._fetch_and_commit(attempt, code, Path(key[0]))
            via = " (completed from the local browser)" if local else ""
            result = {"ok": True, "account": account, "local_browser": local,
                    "reauthorized": attempt.reauthorize, **attempt.scope_info(),
                    "message": f"[Google Workspace: {account} authorized in this profile; credentials saved{via}. Verify with gws_accounts and gws_api.]"}
            return result
        except LoginError as exc:
            if attempt.cancelled:  # Report the fence, not the native side effect.
                exc = LoginError("cancelled")
            elif attempt.expired or time.monotonic() >= attempt.deadline:
                exc = LoginError("expired")
            return {"ok": False, "reason": exc.reason, "local_browser": local, "error": _failure_message(exc.reason, exc.detail)}
        except (OSError, ValueError) as exc:
            reason = getattr(exc, "reason", "companion_unavailable")
            return {"ok": False, "reason": reason, "error": _failure_message(reason)}
        except Exception:
            return {"ok": False, "reason": "internal", "local_browser": local, "error": _failure_message("internal")}

    def finish(self, root, platform, route, user_id, account, callback_url, *, profile=""):
        """Complete a login explicitly on any surface, bound to its original identity."""
        key, attempt = self._lookup(root, platform, route, user_id, account, profile)
        if attempt is None:
            return {"ok": False, "reason": "no_pending", "error": "No pending login for this account in this session."}
        try:
            parsed = self._split_callback(callback_url)
        except ValueError:
            return self._invalid_callback()
        # ponytail: explicit completion uses normal tool arguments, not another ingress hook.
        return self._complete_callback(key, attempt, parsed)

    def _lookup(self, root, platform, route, user_id, account, profile):
        key = self._key(root, platform, route, user_id, profile)
        with self._lock:
            attempt = self._attempts.get(key)
        if attempt is None or not isinstance(account, str) or account.lower() != attempt.account:
            return key, None
        return key, attempt

    def status(self, root, platform, route, user_id, account, *, profile=""):
        """Read-only progress, except a finished outcome is handed over (once), like start()."""
        key, attempt = self._lookup(root, platform, route, user_id, account, profile)
        if attempt is None:
            try:
                registered = isinstance(account, str) and self._backend(root).registered(account.lower())
            except (OSError, ValueError):
                return {"ok": False, "state": "none", "reason": "companion_unavailable",
                        "error": "The public backend is unavailable; account registration is unknown."}
            return {"ok": True, "state": "none", "account_registered": registered}
        taken = self._take_result(key, attempt)
        if taken is not None:
            return dict(taken, state="finished", consumed=True)
        with attempt.lock:
            state = "processing" if attempt.processing else "waiting"
        return {"ok": True, "state": state, "account": attempt.account,
                **attempt.scope_info(),
                "seconds_left": max(0, round(attempt.deadline - time.monotonic()))}

    def _cancel(self, key, attempt):
        """Stop the attempt; cancellation competes only with unblocking a verified slot."""
        with attempt.lock:
            attempt.cancelled = True
            committed = attempt.committed
        self._expire(key, attempt)
        self._remove(key, attempt)
        return committed

    def cancel(self, root, platform, route, user_id, account, *, profile=""):
        key, attempt = self._lookup(root, platform, route, user_id, account, profile)
        if attempt is None:
            return {"ok": False, "reason": "no_pending", "error": "No pending login for this account in this session."}
        committed = self._cancel(key, attempt)
        # committed=True: gws finished first (local browser); the account stays registered.
        return {"ok": True, "cancelled": True, "account": attempt.account, "committed": committed}

    def logout(self, root, account):
        """Stop owned native writers before asking the backend for exclusive logout."""
        if not isinstance(account, str) or not _EMAIL.fullmatch(account):
            return {"ok": False, "reason": "invalid_arguments", "error": "Give the exact Google account email."}
        root, account = Path(root).expanduser().absolute(), account.lower()
        try:
            backend = self._backend(root)
            with self._lock:
                mine = [(k, a) for k, a in self._attempts.items() if k[0] == str(root) and a.account == account]
            for key, attempt in mine:
                self._cancel(key, attempt)
            result = backend.logout(account)
            return dict(result, cancelled_logins=len(mine))
        except TimeoutError:
            return {"ok": False, "reason": "account_busy", "error": _failure_message("account_busy")}
        except (OSError, ValueError) as exc:
            reason = getattr(exc, "reason", "companion_unavailable")
            return {"ok": False, "reason": reason, "error": _failure_message(reason)}

    def _take_result(self, key, attempt):
        """Hand a locally completed outcome over once and release the attempt."""
        with self._lock, attempt.lock:
            if self._attempts.get(key) is not attempt or not attempt.finished or attempt.result is None:
                return None
            self._remove(key, attempt)
            return dict(attempt.result)

    @staticmethod
    def _invalid_callback():
        return {"ok": False, "reason": "invalid_callback", "retryable": True,
                "error": "Invalid callback URL; copy this login's full localhost URL again. "
                         "The login is still pending."}

    @staticmethod
    def _split_callback(text):
        """One bounded URL parser for explicit completion and gateway interception."""
        if not isinstance(text, str) or len(text) > 8192:
            raise ValueError("Invalid callback")
        text = text.strip()
        # urlsplit silently removes some controls; reject them before parsing.
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in text) or "#" in text:
            raise ValueError("Invalid callback")
        if text.lower().startswith("localhost:"):
            text = "http://" + text
        parsed = urlsplit(text)
        if (parsed.scheme != "http" or parsed.hostname != "localhost" or not parsed.port or
                parsed.username is not None or parsed.password is not None):
            raise ValueError("Invalid callback")
        return parsed

    @staticmethod
    def _parse_callback(parsed):
        """Return (code, oauth_error); reject ambiguous responses without consuming the attempt."""
        try:
            query = parse_qs(parsed.query, strict_parsing=True, keep_blank_values=True,
                             max_num_fields=32, errors="strict")
        except ValueError:
            raise LoginError("invalid_callback") from None
        error = query.get("error", [])
        code = query.get("code", [])
        if "error" in query:
            if len(error) != 1 or not error[0] or "code" in query:
                raise LoginError("invalid_callback")
            return None, "access_denied" if error == ["access_denied"] else "oauth_error"
        if len(code) != 1 or not _CODE.fullmatch(code[0]):
            raise LoginError("invalid_callback")
        return code[0], None

    def _complete_callback(self, key, attempt, parsed):
        try:
            redirect = urlsplit(attempt.redirect)
            if parsed.port != redirect.port or (parsed.path or "/") != (redirect.path or "/"):
                raise LoginError("invalid_callback")
            code, oauth_error = self._parse_callback(parsed)
        except LoginError:
            return self._invalid_callback()
        with self._lock, attempt.lock:
            if attempt.finished:
                return self._take_result(key, attempt) or {"ok": False, "reason": "in_progress",
                                                           "error": "The authorization is already being processed."}
            waiting = attempt.processing
            if not waiting:
                attempt.processing = True
        if waiting:
            # The watcher is validating a login that the local browser already
            # completed; report its outcome instead of racing it.
            attempt.done.wait(timeout=max(0.1, attempt.deadline - time.monotonic()) + 5)
            return self._take_result(key, attempt) or {"ok": False, "reason": "in_progress",
                                                       "error": "The authorization is already being processed."}
        if oauth_error:
            result = {"ok": False, "reason": oauth_error, "error": _failure_message(oauth_error)}
        else:
            result = self._run_exchange(key, attempt, code)
        with attempt.lock:
            attempt.result = result
            attempt.finished = True
            attempt.done.set()
        self._expire(key, attempt, finished=True)
        return result

    async def on_message(self, event, **kwargs):
        source = event.source
        platform = getattr(getattr(source, "platform", None), "value", None)
        # An explicitly cleared event actor must never fall back to the route user.
        actor = getattr(event, "user_id", None)
        if actor is None:
            actor = getattr(source, "user_id", None)
        if not platform or not source.chat_id or not actor or self._callback_root is None:
            return None
        try:
            callback_root = str(Path(self._callback_root()).resolve())
        except (OSError, TypeError, ValueError):
            return None
        identity = (str(platform), str(source.chat_id), str(actor),
                    str(getattr(source, "profile", "") or ""))
        with self._lock:
            matching = [(key, attempt) for key, attempt in self._attempts.items()
                        if key[0] == callback_root and key[1:5] == identity]
        if not matching:
            return None
        text = str(event.text or "").strip()
        # ponytail: intercept plain localhost pastes only, not arbitrary links or prose.
        if not text[:17].lower().startswith(("localhost:", "http://localhost:")):
            return None
        try:
            parsed = self._split_callback(text)
        except ValueError:
            result = self._invalid_callback()
        else:
            matches = [(key, a) for key, a in matching if parsed.port == urlsplit(a.redirect).port]
            if not matches:
                return None
            result = self._invalid_callback()
            if len(matches) == 1:
                key, attempt = matches[0]
                try:
                    store = kwargs.get("session_store")
                    if store is None:
                        raise ValueError("Missing bound session store")
                    logical = store._generate_session_key(source)
                    if (logical, store.peek_session_id(logical)) == key[5:]:
                        result = await asyncio.to_thread(self._complete_callback, key, attempt, parsed)
                    else:
                        result = {"error": "Callback not forwarded: return to the original session."}
                except (Exception, asyncio.CancelledError):
                    result = {"error": _failure_message("internal")}
        # All recognised paths share redaction and best-effort deletion, even malformed pastes.
        message = result.get("message") or f"[Google Workspace: {result['error']}]"
        gateway = kwargs.get("gateway")
        message_id = str(getattr(source, "message_id", "") or getattr(event, "message_id", "") or "")
        if gateway is not None and message_id:
            try:
                adapter = gateway._delivery_adapter_for(source)
                if adapter is not None:
                    await asyncio.wait_for(adapter.delete_message(str(source.chat_id), message_id), timeout=2)
            except (Exception, asyncio.CancelledError):
                pass  # Best-effort platform deletion, not a security guarantee.
        return {"action": "rewrite", "text": message}
