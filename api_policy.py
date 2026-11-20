"""Private logout approval only; public API policy belongs to google-workspace."""


def make_pre_tool_call_hook():
    def hook(tool_name="", args=None, **kwargs):
        if tool_name != "gws_logout":
            return None
        args = args if isinstance(args, dict) else {}
        account = str(args.get("account") or "?")
        return {"action": "approve", "rule_key": f"gws:{account}:logout",
                "message": f"Remove local Google credentials for {account} from this profile? "
                           "This does not revoke Google-side consent or delete Google data."}
    return hook
