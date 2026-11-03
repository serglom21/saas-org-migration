# org-copy

Copy Sentry organization settings from one region to another through the public API. The destination organization must already exist. The script does not move events, issue history, billing, or releases.

## Install

Python 3.11 or newer is required.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Tokens

Create one org auth token in the source organization and one in the destination organization. Each token is limited to that organization and region.

Source token:

- `org:read`
- `project:read`
- `member:read`
- `team:read`
- `alerts:read`

Destination token:

- `org:write`
- `project:write`
- `member:read`

Add `member:write` on the destination token only if you pass `--send-invites`. Inviting someone as owner can require `member:admin`.

These scopes are separate. `org:write` does not include `project:write` or `member:read`.

Do not commit the tokens. Pass them as environment variables:

```bash
export SOURCE_TOKEN="..."
export DEST_TOKEN="..."
```

## What is copied

- Organization settings, including data scrubbing
- Teams, including a rename when the slug already exists
- Team membership for people who already belong to the destination organization
- Projects, project settings, inbound filters, and ownership rules
- New client keys, with new DSNs. The source DSN secret is not reused.
- Alerts. Actions that depend on an integration, such as Slack or PagerDuty, are dropped and listed in the checklist.
- Metric monitors
- Cron monitors
- Custom dashboards. Prebuilt dashboards are skipped.
- Discover saved queries and recent searches
- Issue views that belong to the token user
- Data forwarders, including their configuration

## What stays manual

`manual-checklist.md` lists the items the API cannot write:

- SSO, SAML, and SCIM
- Integrations, repositories, code mappings, code owners, and service hooks
- Uptime monitors
- Organization auth tokens (names and scopes only)
- Releases, source maps, and debug files
- Hidden environments, until events create them
- Replay access, until invited members accept
- Past events, issue history, replays, logs, and audit history

Switch SDK DSNs last, after alerts in the destination organization are working. New DSNs are written to `dsn-map.json`.

## Run

Export reads the source organization and writes `snapshot.json` plus a checklist. It does not change either organization.

```bash
org-copy export \
  --source-host https://us.sentry.io \
  --source-org SOURCE_ORG \
  --source-token "$SOURCE_TOKEN"
```

Plan compares that snapshot with the destination and prints the writes it would make. It does not write.

```bash
org-copy plan \
  --dest-host https://de.sentry.io \
  --dest-org DEST_ORG \
  --dest-token "$DEST_TOKEN"
```

Apply writes the settings. Run it again to skip objects that already match by slug or name.

```bash
org-copy apply \
  --dest-host https://de.sentry.io \
  --dest-org DEST_ORG \
  --dest-token "$DEST_TOKEN"
```

`SOURCE_HOST` defaults to `https://us.sentry.io`. `DEST_HOST` defaults to `https://de.sentry.io`. Org slugs and tokens can also be set with `SOURCE_ORG`, `DEST_ORG`, `SOURCE_TOKEN`, and `DEST_TOKEN`.

The command exits with status 1 when an export or apply step fails. Other steps still run. Read the checklist for the failures.

## Flags

`--send-invites` emails people who are not already members of the destination organization. Without it, existing members are added to the copied teams and nobody new is invited.

`--no-include-forwarders` skips data forwarders. Forwarders are copied by default. Their secrets are sent to the API and are not printed.

`--hide-environments` marks the source's hidden environments as hidden on the destination. Run this after the destination has received events for those environments.

`--apply-replay-access` copies the replay allow-list. Run this after members have accepted their invites, matched by email.

## Output files

These files are gitignored because they contain customer settings and credentials:

- `snapshot.json` holds the source export. Data-forwarder secrets stay in this file.
- `state.json` maps source ids to destination ids so a later apply does not create duplicates.
- `dsn-map.json` lists the new destination DSNs.
- `manual-checklist.md` lists work that still has to be done by hand.

All four are written with mode `0600`.
