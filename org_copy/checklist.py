"""Manual checklist for settings the API cannot copy."""

from __future__ import annotations

from typing import Any

from org_copy.remap import PROJECT_OPTION_KEYS, member_email


def render_checklist(
    snapshot: dict[str, Any],
    *,
    dest_org: str | None = None,
    actions: list[str] | None = None,
    failures: list[dict[str, Any]] | None = None,
    dropped_actions: list[dict[str, str]] | None = None,
    dsn_map: list[dict[str, str]] | None = None,
    rejected_org_fields: list[str] | None = None,
    rejected_project_options: list[dict[str, str]] | None = None,
    notes: list[str] | None = None,
) -> str:
    source = snapshot.get("source") or {}
    organization = snapshot.get("organization") or {}
    lines: list[str] = [
        "# Manual settings checklist",
        "",
        f"Source org: `{source.get('org')}` ({source.get('host')})",
        f"Destination org: `{dest_org}`" if dest_org else "Destination org: created by hand before apply.",
        "",
        "Switch SDK DSNs last, after alerts in the destination org are working.",
        "",
        "## Does not move",
        "",
        "- Past events, issue history and state, replays, logs, audit logs, and usage.",
        "- Billing stays on the new org.",
        "- Releases, source maps, and debug files have to be uploaded again from CI.",
        "",
    ]
    if dest_org:
        _section_review(lines, snapshot)
        _section_finish(lines, snapshot)
        _section_gaps(lines)
    _section_sso(lines, organization, snapshot.get("authProvider"))
    _section_integrations(lines, snapshot)
    _section_code(lines, snapshot)
    _section_tokens(lines, snapshot)
    _section_apps(lines, snapshot)
    _section_releases(lines, snapshot)
    _section_dsn(lines, dsn_map or [])
    _section_hidden(lines, snapshot)
    _section_members(lines, snapshot)
    _section_replay(lines, snapshot)
    _section_alerts(lines, dropped_actions or [])
    _section_rejected(lines, rejected_org_fields or [], rejected_project_options or [])
    _section_forwarders(lines, snapshot)
    if organization.get("require2FA"):
        lines.extend(
            [
                "## 2FA",
                "",
                "- Source org requires 2FA. Apply can only turn it on with a personal token whose user has 2FA. Confirm it is on in the destination org's security settings.",
                "",
            ]
        )
    if notes:
        lines.extend(["## Notes", ""])
        lines.extend(f"- {note}" for note in notes)
        lines.append("")
    if failures or snapshot.get("exportErrors"):
        lines.extend(["## Failures", ""])
        for item in snapshot.get("exportErrors") or []:
            lines.append(f"- Export `{item.get('step')}`: {item.get('detail')}")
        for item in failures or []:
            lines.append(f"- {item.get('step')}: {item.get('detail')}")
        lines.append("")
    if actions:
        lines.extend(["## Apply log", ""])
        lines.extend(f"- {action}" for action in actions)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


REVIEW_ORG_FIELDS = (
    "require2FA",
    "dataScrubber",
    "dataScrubberDefaults",
    "scrubIPAddresses",
    "sensitiveFields",
    "safeFields",
    "relayPiiConfig",
    "trustedRelays",
    "defaultRole",
)


def _section_review(lines: list[str], snapshot: dict[str, Any]) -> None:
    projects = snapshot.get("projects") or []
    detector_types = [str(detector.get("type")) for project in projects for detector in project.get("detectors") or []]
    organization = snapshot.get("organization") or {}
    counts = (
        ("Teams", len(snapshot.get("teams") or [])),
        ("Projects", len(projects)),
        ("Members, after invites are sent", len(snapshot.get("members") or [])),
        ("Alerts", len(snapshot.get("workflows") or [])),
        ("Metric monitors", detector_types.count("metric_issue")),
        ("Cron monitors", len(snapshot.get("monitors") or [])),
        ("Uptime monitors", detector_types.count("uptime_domain_failure")),
        ("Custom dashboards", sum(1 for item in snapshot.get("dashboards") or [] if not item.get("prebuiltId"))),
        ("Discover saved queries", len(snapshot.get("savedQueries") or [])),
        ("Explore saved queries", sum(1 for item in snapshot.get("exploreQueries") or [] if not item.get("isPrebuilt"))),
        (
            "Issue views shared with the organization",
            sum(len(views) for views in (snapshot.get("issueViews") or {}).values()),
        ),
        ("Data forwarders", len(snapshot.get("forwarders") or [])),
    )
    lines.extend(
        [
            "## Review the destination",
            "",
            "- Apply exits with status 1 when a step failed. Each failure is listed under Failures.",
            "- The source has these. The destination should have the same:",
        ]
    )
    lines.extend(f"  - {label}: {count}" for label, count in counts)
    lines.extend(
        [
            "- Each alert is under the same project or monitor as in the source. "
            "Alerts with the same name show once per project.",
            "- Compare these org settings by hand. A rejected org setting can be dropped without a failure:",
        ]
    )
    lines.extend(f"  - `{field}`: {_describe(organization.get(field))}" for field in REVIEW_ORG_FIELDS)
    lines.extend(
        [
            "- For each project, compare settings, inbound filters, ownership rules, and client keys.",
            "- If apply ran with `--send-invites`, each person under People was invited with that role and those teams.",
            "",
        ]
    )


def team_admins_to_set(snapshot: dict[str, Any]) -> list[str]:
    """Members who were team admins in the source. Invites don't copy team roles."""
    return [
        f"{member_email(member)} on {item.get('teamSlug')}"
        for member in snapshot.get("members") or []
        if (member.get("orgRole") or "member") == "member"
        for item in member.get("teamRoles") or []
        if isinstance(item, dict) and item.get("role") == "admin"
    ]


def _section_finish(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Finish by hand", ""])
    admins = team_admins_to_set(snapshot)
    if admins:
        lines.append(
            "- Invites do not copy team roles. After people accept, make them team admins in the UI "
            "or run `update-team-admins`:"
        )
        lines.extend(f"  - {admin}" for admin in admins)
    lines.extend(
        [
            "- Alert recipients and owners who were not members when apply ran were left out. "
            "If Alert actions to recreate after integrations marks any as "
            "\"target is not a member of the destination org yet\", add them after those people join.",
            "- If Failures lists ownership steps, those rules were not saved. "
            "Enter them again after the people they name join.",
        ]
    )
    lines.append(
        "- Issue views that members kept private are not copied. Sentry does not return them, "
        "so each member recreates their own."
    )
    lines.append("")


def _section_gaps(lines: list[str]) -> None:
    lines.extend(
        [
            "## Known gaps to check",
            "",
            "- Alert conditions that name a user or team, such as assigned to, keep the source IDs.",
            "- Metric monitors lose group by. Compare anomaly detection settings.",
            "- Changes to the default issue, error, and performance detectors in each project are not copied.",
            "- Dashboard widgets lose thresholds and descriptions.",
            "- A destination project that already had the same slug had its settings, filters, and keys replaced.",
            "- An invite fails when one of its teams was not created. Look for invite steps under Failures.",
            "- Uptime monitors fail to create when the destination has no uptime seats left.",
            "- Auto-detected uptime monitors are created as manual monitors.",
            "- Two metric monitors with the same name in one project are copied as one.",
            "- Recent searches are not copied. Sentry only returns the token's own, so each person's start empty.",
            "",
        ]
    )


def _describe(value: Any) -> str:
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, (list, dict)):
        return f"{len(value)} listed" if value else "none"
    if value in (None, ""):
        return "not set"
    text = str(value)
    return f"`{text}`" if len(text) <= 40 else "set"


def _section_sso(lines: list[str], organization: dict[str, Any], provider: Any) -> None:
    lines.extend(["## SSO, SAML, and SCIM", ""])
    if organization.get("hasAuthProvider") or provider:
        name = ""
        if isinstance(provider, dict):
            name = provider.get("provider") or provider.get("name") or ""
        lines.append(
            f"- Reconfigure the IdP app for the new org (source provider: {name or 'configured'}). "
            "ACS and SCIM endpoints change with the org."
        )
    else:
        lines.append("- No auth provider was listed on the source org.")
    lines.append("")


def _section_integrations(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Integrations", ""])
    integrations = snapshot.get("integrations") or []
    if not integrations:
        lines.append("- No integrations were listed. Reconnect Slack, PagerDuty, source control, Jira, and the rest by hand.")
    else:
        lines.append("- Reconnect each integration, including code mappings and team or user mappings:")
        for item in integrations:
            lines.append(f"  - {item.get('provider') or item.get('name')}: {item.get('name')} ({item.get('status') or 'installed'})")
    lines.append("")


def _section_code(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Code mappings and code owners", ""])
    mappings = snapshot.get("codeMappings") or []
    if mappings:
        for item in mappings:
            lines.append(
                f"- Mapping `{item.get('project')}` -> `{item.get('repo')}` "
                f"(stack `{item.get('stackRoot')}`, source `{item.get('sourceRoot')}`)."
            )
    else:
        lines.append("- No code mappings were listed.")
    found = False
    for project in snapshot.get("projects") or []:
        for owner in project.get("codeowners") or []:
            found = True
            lines.append(f"- Re-import code owners on `{project.get('slug')}` after source control is connected.")
            break
        for hook in project.get("serviceHooks") or []:
            lines.append(f"- Recreate webhook on `{project.get('slug')}`: {hook.get('url')} events={hook.get('events')}")
    if not found:
        lines.append("- No code owners were listed.")
    lines.append("")


def _section_tokens(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Org auth tokens", ""])
    tokens = snapshot.get("authTokens") or []
    if not tokens:
        lines.append("- Create new org auth tokens in the destination UI. Token secrets are not copied.")
    else:
        lines.append("- Create new tokens with the same names and scopes. The old secret is not copied:")
        for token in tokens:
            scopes = ", ".join(str(scope) for scope in (token.get("scopes") or []))
            lines.append(f"  - {token.get('name') or token.get('id')} ({scopes})")
    lines.append("")


def _section_apps(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Custom Sentry apps", ""])
    installs = snapshot.get("sentryAppInstallations") or []
    if not installs:
        lines.append("- Reinstall custom Sentry apps on the destination org.")
    else:
        for item in installs:
            lines.append(f"- Reinstall app `{item.get('app')}`.")
    lines.append("")


def _section_releases(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Releases and debug files", ""])
    lines.append("- Re-upload releases, source maps, and debug symbols from the pipeline.")
    lines.append("- Release thresholds are not copied.")
    for project in snapshot.get("projects") or []:
        if project.get("latestRelease"):
            lines.append(f"- `{project.get('slug')}` last saw release `{project.get('latestRelease')}`.")
    lines.append("")


def _section_dsn(lines: list[str], dsn_map: list[dict[str, str]]) -> None:
    lines.extend(["## DSN cutover", ""])
    if not dsn_map:
        lines.append("- New DSNs are written to `dsn-map.json` on apply. Point SDKs at them only after the destination is ready.")
    else:
        lines.append("- Update SDK config to these DSNs:")
        for item in dsn_map:
            lines.append(f"  - `{item.get('project')}` / `{item.get('key')}`: `{item.get('dsn')}`")
    lines.append("")


def _section_hidden(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Hidden environments", ""])
    found = False
    for project in snapshot.get("projects") or []:
        names = project.get("hiddenEnvironments") or []
        if names:
            found = True
            joined = ", ".join(names)
            lines.append(
                f"- `{project.get('slug')}` hides {joined}. "
                "Hide them in project settings after events create them, or re-run apply with `--hide-environments`."
            )
    if not found:
        lines.append("- No hidden environments were listed.")
    lines.append("")


def _section_members(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## People", ""])
    lines.append("- Invites are not sent unless apply is run with `--send-invites`.")
    for member in snapshot.get("members") or []:
        teams = ", ".join(member.get("teamSlugs") or []) or "no teams"
        lines.append(f"- {member_email(member)} role `{member.get('orgRole')}` teams: {teams}")
    requests = snapshot.get("inviteRequests") or []
    if requests:
        lines.extend(
            [
                "",
                "Waiting for approval in the source, so not invited. Approve them in the source and export again, "
                "or invite them in the destination:",
            ]
        )
        lines.extend(f"- {item.get('email')} role `{item.get('role')}`" for item in requests)
    lines.append("")


def _section_replay(lines: list[str], snapshot: dict[str, Any]) -> None:
    emails = snapshot.get("replayAccessEmails") or []
    if not emails:
        return
    lines.extend(
        [
            "## Replay access",
            "",
            "- After these members accept their invites, add them to replay access in org settings, "
            "or re-run apply with `--apply-replay-access`:",
        ]
    )
    lines.extend(f"  - {email}" for email in emails)
    lines.append("")


def _section_alerts(lines: list[str], dropped: list[dict[str, str]]) -> None:
    lines.extend(["## Alert actions to recreate after integrations", ""])
    if not dropped:
        lines.append("- No integration alert actions were dropped.")
    else:
        for item in dropped:
            lines.append(f"- `{item.get('rule')}`: {item.get('action')}")
    lines.append("")


def _section_rejected(
    lines: list[str], org_fields: list[str], project_options: list[dict[str, str]]
) -> None:
    if not org_fields and not project_options:
        return
    lines.extend(["## Settings the API rejected", ""])
    for field in org_fields:
        lines.append(f"- Org field `{field}` was not accepted. Set it in the UI.")
    for item in project_options:
        if item.get("field") in PROJECT_OPTION_KEYS or True:
            lines.append(
                f"- Project `{item.get('project')}` field `{item.get('field')}` was not accepted. Set it in the UI."
            )
    lines.append("")


def _section_forwarders(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Data forwarders", ""])
    forwarders = snapshot.get("forwarders") or []
    if not forwarders:
        lines.append("- No data forwarders were listed.")
    else:
        lines.append("- Forwarder credentials stay in `snapshot.json` and are not printed here.")
        for item in forwarders:
            projects = ", ".join(
                project.get("slug") or ""
                for project in item.get("enrolledProjects") or []
                if isinstance(project, dict)
            )
            lines.append(f"- Provider `{item.get('provider')}` enrolled projects: {projects or '(none)'}")
    lines.append("")
