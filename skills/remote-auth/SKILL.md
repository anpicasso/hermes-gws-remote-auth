---
name: remote-auth
description: "Use for remote Google consent and local logout."
---

# Remote native Google authorization

Use `gws_login` with the exact account and a trusted bound session. Open its URL;
if the browser is remote, paste the complete localhost callback in the originating chat, topic and session.
After a session reset, start a new attempt; do not reuse the old link.
`action=status` consumes the result; `action=cancel` stops the pending attempt.
Run `hermes gws setup EMAIL` locally first if the account lacks a Desktop client. The native wizard requires gcloud and Cloud Console input. Use `reauthorize=true` for replacement. Native writes have no rollback; failed or interrupted login leaves routing blocked. Request only the scopes needed; full is the existing default.
Never request passwords, client JSON, exported tokens or standalone codes.
Explicit callback arguments pass through model/history. Interception and message
deletion are best effort, not an erasure guarantee. Expired callbacks are not caught.

The public `google-workspace` plugin must be loaded in the same profile with the
`gws-native-account-v2` backend. It owns binary selection, process/path isolation,
the routing block, identity checks, lifecycle locks and native local logout.
Configure only `plugins.entries.google-workspace.settings.gws_bin`; the private
plugin has no binary override and never invokes interactive `hermes gws login`.
Stop watches and finish cleanup before changing account credentials. Missing or
incompatible companions fail closed. Pending status/cancel remain available.

Delegated children cannot reuse the originating session’s identity. `gws_logout` requires Hermes approval, cancels this manager’s pending attempts and invokes native local logout. Finish or cancel another process’s writer before retrying. It may leave the client configuration
and slot directory. It does not revoke Google consent or delete Google data.
The local operator alternatives remain `hermes gws setup/login/status/accounts/logout`.
