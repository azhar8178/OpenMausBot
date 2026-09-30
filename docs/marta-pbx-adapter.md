# Marta PBX session adapter

This adapter connects one signed-in OpenMausBot browser session and one Marta
thread to the PBX-AI identity authority. It does not merge the applications,
copy PBX users into OpenMausBot, or give Marta a PBX password.

## Security boundary

- The PBX remains the authority for users, roles and granular permissions.
- A browser receives only safe connection status and identity display fields.
- OpenMausBot persists an opaque PBX session grant in
  `/data/marta-pbx-sessions.json` with mode `0600`.
- A fresh, short-lived actor grant is requested for every Marta turn and is
  injected only into the configured local stdio MCP process.
- Handoff codes, PKCE verifiers and actor grants are never persisted.
- The binding is scoped to the OpenMaus session, Marta bot and exact thread.
- Session logout, revocation or expiry deletes local bindings and attempts PBX revocation.
- Marta rejects routines, webhooks, queued/steered messages, channel turns,
  peer delegation, card continuations and cloud execution.
- The Marta bot must stay on Ask, with no remembered approvals, computer Off,
  browser and connected apps disabled, no team authority, and exactly one MCP server.

## Configuration

Set these only on the dedicated Marta OpenMausBot deployment:

```dotenv
OMB_MARTA_BOT_ID=<stored-marta-bot-id>
OMB_MARTA_MCP_SERVER=marta-readonly
OMB_MARTA_PBX_PUBLIC_URL=https://pbx.example.com
OMB_MARTA_PBX_INTERNAL_URL=http://marta-gateway:3001
OMB_MARTA_PBX_CONNECT_PATH=/marta-connect
MARTA_HANDOFF_TOKEN=<same-64-character-machine-secret-as-the-PBX>
```

The public PBX origin must be HTTPS and contain no path. The internal origin
may be HTTP on the private Docker network. The machine token must be at least
32 characters. OpenMausBot fails closed for Marta when any value is invalid,
but other bots remain unaffected.

The PBX browser page at `/marta-connect` authenticates the current PBX user,
POSTs to its existing `/api/auth/marta-handoff` endpoint with the received
`state`, PKCE `challenge`, Marta bot id and thread id, then redirects to:

```text
https://<marta-openmaus-host>/api/auth/pbx/callback?state=...&code=...
```

The internal version-1 contract remains:

- `POST /api/marta/v1/handoff/consume`
- `POST /api/marta/v1/session/check`
- `POST /api/marta/v1/session/revoke`

## Marta bot hardening

1. Set approval to **Ask** and remove every Always allowed entry.
2. Set **Works on** to **Off**.
3. Disable Browser and Connected apps.
4. Remove Chief of Staff, managed-team and peer permissions.
5. Select exactly the `marta-readonly` local MCP server.

The server verifies this policy before every Marta turn. A UI setting alone is
not treated as a security boundary.

## Rollout and rollback

Build and test this feature branch in an isolated fixture. Do not merge or
deploy it without separate approval. To disable it, remove the `OMB_MARTA_*`
values and `MARTA_HANDOFF_TOKEN`, then restart OpenMausBot. Existing Sophie,
PBX, Odoo and non-Marta OpenMaus behavior remains on its original path.
