"""Optional private OAuth companion. Registers no public Workspace API tools."""
import json
from pathlib import Path

from .oauth import LoginManager, _EMAIL
from .api_policy import make_pre_tool_call_hook


def register(ctx):
    from hermes_constants import get_hermes_home
    from gateway.session_context import _bound_session_value
    from agent.delegation_context import is_delegated_child_process_context

    home = get_hermes_home().absolute()
    root = home / "gws-oauth"
    manager = LoginManager(callback_root=lambda: get_hermes_home() / "gws-oauth")
    ctx.on_unload(manager.close)
    ctx.register_hook("pre_tool_call", make_pre_tool_call_hook())
    ctx.register_skill("remote-auth", Path(__file__).parent / "skills/remote-auth/SKILL.md")

    def origin(kwargs):
        if get_hermes_home().resolve() != home:
            raise ValueError("profile_mismatch")
        if is_delegated_child_process_context() or _bound_session_value("HERMES_CRON_SESSION") == "1":
            raise ValueError("no_session_identity")

        def field(name):
            value = _bound_session_value("HERMES_SESSION_" + name)
            return value if isinstance(value, str) else None

        platform = field("PLATFORM") or field("SOURCE")
        chat, actor, profile = field("CHAT_ID"), field("ACTOR_ID"), field("PROFILE")
        logical, physical = field("KEY"), field("ID")
        if (not platform or not actor or not logical or not physical or kwargs.get("session_id") != physical
                or profile is None or chat is None):
            raise ValueError("no_session_identity")
        if profile and profile != (getattr(ctx, "profile_name", None) or "default"):
            raise ValueError("profile_mismatch")
        return platform, (chat, logical, physical), actor, profile, bool(chat)

    def login(args, **kwargs):
        try:
            platform, chat, actor, profile, gateway_chat = origin(kwargs)
            account = args.get("account")
            if not isinstance(account, str) or not _EMAIL.fullmatch(account):
                raise ValueError("invalid_arguments")
            action = args.get("action", "start")
            if action not in ("start", "status", "cancel") or (
                    action != "start" and args.get("callback_url") is not None):
                raise ValueError("invalid_arguments")
            if action in ("status", "cancel"):
                result = getattr(manager, action)(root, platform, chat, actor, account, profile=profile)
            elif args.get("callback_url") is not None:
                result = manager.finish(root, platform, chat, actor, account, args["callback_url"], profile=profile)
            else:
                result = manager.start(
                    root, platform, chat, actor, account,
                    (lambda callback: ctx.register_hook("pre_gateway_dispatch", callback)) if gateway_chat else None,
                    profile=profile, scope_mode=args.get("scope_mode", "full"),
                    scopes=args.get("scopes"), reauthorize=args.get("reauthorize", False))
        except ValueError as exc:
            reason = str(exc) if str(exc) in {"profile_mismatch", "no_session_identity", "invalid_arguments"} else "invalid_arguments"
            result = {"ok": False, "reason": reason, "error": "A trusted bound session and valid login arguments are required."}
        except Exception:
            result = {"ok": False, "reason": "local_error", "error": "Login could not run safely."}
        return json.dumps(result)

    def logout(args, **kwargs):
        try:
            origin(kwargs)
            account = args.get("account")
            if not isinstance(account, str) or not _EMAIL.fullmatch(account):
                raise ValueError("invalid_arguments")
            account = account.lower()
            # The shared backend holds lifecycle across native logout and the watch check.
            result = manager.logout(root, account)
        except ValueError as exc:
            reason = str(exc) if str(exc) in {"profile_mismatch", "no_session_identity", "invalid_arguments"} else "local_error"
            result = {"ok": False, "reason": reason, "error": "Local credentials could not be removed safely."}
        except Exception:
            result = {"ok": False, "reason": "local_error", "error": "Local credentials could not be removed safely."}
        return json.dumps(result)

    ctx.register_tool(name="gws_login", toolset="gws_remote_auth", handler=login, schema={
        "name": "gws_login",
        "description": "Authorize an exact Google account in this single-operator profile. Full consent is the default. Open the consent URL; a local browser completes automatically. Otherwise paste the localhost callback in the same chat or use callback_url (explicit arguments pass through model/history). status reads the one-shot result; cancel stops the pending login. Native reauthorization writes in place; routing stays blocked unless identity verification succeeds. No plugin rollback. Run hermes gws setup EMAIL locally for first-time client setup. Never request passwords, exported tokens or standalone codes.",
        "parameters": {"type": "object", "additionalProperties": False, "properties": {
            "account": {"type": "string", "description": "Exact Google email"},
            "action": {"type": "string", "enum": ["start", "status", "cancel"], "default": "start"},
            "callback_url": {"type": "string", "description": "Full localhost callback for this session's pending login"},
            "scope_mode": {"type": "string", "enum": ["default", "readonly", "full", "custom"], "default": "full"},
            "scopes": {"type": "array", "items": {"type": "string"}},
            "reauthorize": {"type": "boolean", "default": False}}, "required": ["account"]}})
    ctx.register_tool(name="gws_logout", toolset="gws_remote_auth", handler=logout, schema={
        "name": "gws_logout",
        "description": "After Hermes approval, cancel pending account logins and remove only local credentials. Google consent and data are not deleted. Stop watches and finish cleanup first. Prefer gws_login reauthorize=true for renewal.",
        "parameters": {"type": "object", "additionalProperties": False,
                       "properties": {"account": {"type": "string"}}, "required": ["account"]}})
