# gws-remote-auth (optional, outside the catalog)

Only `gws_login` and `gws_logout` are registered. The public [`gws-workspace`](https://github.com/anpicasso/hermes-google-workspace)
plugin owns accounts, API execution, health checks and watches. This optional
companion is not needed for native terminal login or public API use. Do not
install it beside an older plugin that also registers these two tool names.

## Requirements and setup

- A compatible Hermes runtime and the public `gws-workspace` plugin loaded in the
  same profile and interpreter (tested with `plugins.isolation: in_process`). The
  manifest range `>=0.9.1,<1.0.0` is advisory: the loaded plugin must also expose
  `gws-native-account-v2`. A version number alone is not enough.
- POSIX process locks for native auth writes. Native `gws` on PATH, or configure the executable once at
  `plugins.entries.gws-workspace.settings.gws_bin`. Remove the old private
  override; it is ignored. The public setting is resolved per operation; a
  pending login retains the binary that launched it for identity verification.
- Set up a Desktop OAuth client **for this account** with the public `hermes gws setup EMAIL` terminal command. Native gws may sign into gcloud, select/create a project, enable APIs, and ask you to create a Desktop client in Cloud Console and enter its ID and secret in the native terminal. It is not unattended. Existing per-account clients do not need setup. The remote companion does not run setup in chat or import a global/profile client. Never send client secrets, passwords or tokens through chat.

This repository is public, but the plugin is **not being submitted to the Hermes catalog**. Remote consent and callback forwarding are opt-in conveniences with chat-history exposure and gateway-specific host bindings; they are separate from the Workspace tools/watch plugin and do not claim catalog compliance. Install directly with Hermes's native plugin installer:

    hermes plugins install anpicasso/hermes-gws-remote-auth --enable

Install the compatible public plugin first. Neither plugin patches Hermes core.

The stable native store is `$HERMES_HOME/gws-oauth/accounts/<lowercase-email>/`. Paths and process isolation come from the public plugin. No account router, lock implementation or credential-store copy is shipped here. Quiesce old workers/attempts before upgrading the pair.

## Login, reauthorization and logout

1. In a trusted bound session, call `gws_login` with the exact Google email.
   The default is `scope_mode="full"`; `readonly`, native `default`, and
   `custom` with an explicit `scopes` array are also supported.
2. Open the returned consent URL and select that exact Google account.
   On the Hermes host, native gws completes automatically. Use
   `action="status"` with the same account to consume the one-shot outcome.
3. On another device, the localhost redirect normally fails to connect.
   Paste that complete URL into the originating chat, or pass `callback_url`
   to `gws_login` in the same bound session. Protocol-less `localhost:<port>`
   URLs are accepted; ambiguous, wrong-path and duplicate-code URLs are not.
4. `action="cancel"` stops the attempt; `reauthorize=true` explicitly permits replacing existing credentials. Native login writes in place and has no rollback. On failure or cancellation the native credentials may have changed, but the account cannot be routed until a verified login. If an old API cache or plaintext fallback exists, explicitly log out before replacement.
5. `gws_logout(account=...)` requests Hermes approval. It cancels this manager's pending attempts for the account, then invokes native `gws auth logout`; finish or cancel a writer in another process first. The directory and Desktop client can remain. Logout does not revoke Google consent or delete Google data. Stop watches and finish cleanup first.

Multiple account slots coexist; there is at most one pending login per
profile home, platform, chat, actor, logical route and physical session. Full consent is requested, not a claim
that all scopes were granted. Public `gws_accounts` owns granted-scope reporting.

## Companion lifecycle contract and integration

At runtime the companion resolves exactly one active `gws-native-account-v2`
instance from Hermes's already loaded `hermes_plugins.gws_workspace` namespace
(including profile-qualified names), matching the exact profile store. It never
imports a checkout by path, runs the interactive `hermes gws` CLI, or falls back
to another profile. Missing, incompatible, ambiguous or unloaded backends refuse
mutations; an owned pending attempt can still be inspected or cancelled.

The public backend holds the per-account watch lifecycle lock for the full native operation. It drains native API calls and marks the account unroutable before launch. This supervisor reads the consent URL, waits for a local browser or forwards the matching callback, and checks cancellation/deadline before the backend unblocks a verified account. Native gws alone performs OAuth exchange, persistence, decryption and refresh. No SQLite transaction is kept open during consent. Another writer cannot start for the same account; active/matched watches and unfinished cleanup refuse credential changes.

## Security and limitations

- Intended for a trusted single operator per profile, not an account ACL system.
  Tool origins require a context-bound route key, platform, chat/session and
  strict current actor. A cleared actor never falls back to route `USER_ID`.
  Profile-home mismatch and unbound/global-only routes are refused. Older CLI
  or API frontends without bound key/actor metadata cannot use this tool; use
  native terminal login or a frontend providing those host bindings.
- Tool calls require host-bound logical and physical session IDs, and the physical
  ID must match the dispatched invocation. Delegated children and scheduled runs
  are refused. Ingress matches profile home, platform, actor, chat, original
  logical route and current physical session before forwarding to the captured
  loopback port/path. A reset or different topic cannot take over the attempt.
  The host session lookup is an ingress-time check, not an atomic lock against
  future session resets; a local browser can still complete an already started
  native process. Unmatched/expired callbacks are not globally intercepted.
- Explicit `callback_url` arguments pass through the model/history. Gateway
  rewrite and best-effort message deletion reduce exposure but cannot erase
  platform logs or prior captures. Never paste expired callback URLs.
- Credentials and refresh remain owned by native gws. The native loopback
  server is reachable by local processes; use a trusted host. No new OAuth
  server, framework, native state/PKCE implementation or token export is added.
- Attempts are memory-owned and cannot resume after restart. The nonsecret routing block survives a failed or interrupted native write; retry a verified login or log out locally. Old staging/backup directories are left untouched. This suite exercises Linux only.
- Tests use synthetic clients, a fake native loopback for successful exchanges, and an installed gws process stopped before consent. No Google account is contacted.
  The paired check is offline integration, not real consent or live Google E2E.
- The companion depends on Hermes's bound-only context reader, delegation
  guard and gateway session-store lookup. If your host lacks these bindings,
  use the local operator CLI. A hosted-isolation placeholder is not a live
  session store. No public catalog or Windows support is claimed. Doctor in an
  empty home warns about the lazy ingress hook and missing advisory dependency.

## Offline verification

Use a dependency-complete Hermes interpreter, the native `gws` executable on PATH, both matching source checkouts, and
fresh, isolated homes. From this repository (set `TMPDIR` to a scratch directory):

```sh
export HOME="$(mktemp -d)" HERMES_HOME="$(mktemp -d)"
export HERMES_AGENT_SRC=/path/to/pinned/hermes-agent PYTHONPATH=/path/to/pinned/hermes-agent
export GWS_PUBLIC_SRC=/path/to/matching/hermes-google-workspace-split
export HERMES_DISABLE_LAZY_INSTALLS=1 PYTHONDONTWRITEBYTECODE=1
python -m unittest discover -s tests -v
python tests/pair_check.py --public "$GWS_PUBLIC_SRC"
```

`test_pair_native.py` uses the real namespaced loader, tool/hook dispatch,
CLI parser, session store and synthetic native subprocesses; `pair_check.py`
exercises both watch-start/logout race orderings. Neither contacts Google.
