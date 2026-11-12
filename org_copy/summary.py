"""Summary printed at the end of apply: what was migrated, what went wrong, and what is left to do."""

from __future__ import annotations

from typing import Any

from org_copy.apply import ApplyReport
from org_copy.checklist import team_admins_to_set


def render_summary(snapshot: dict[str, Any], report: ApplyReport, dest_org: str) -> str:
    lines = [f"Summary for {dest_org}", "", "Migrated:"]
    lines.extend(f"  {section.label}: {section.summary}" for section in report.sections)

    failures = [f"Reading the source, {item.get('step')}: {item.get('detail')}" for item in snapshot.get("exportErrors") or []]
    failures.extend(f"{item.get('step')}: {item.get('detail')}" for item in report.failures)
    lines.extend(["", f"Went wrong ({len(failures)}):" if failures else "Went wrong: nothing."])
    lines.extend(f"  - {item}" for item in failures)

    pending = _pending(snapshot, report)
    lines.extend(["", f"Still to do ({len(pending)}):" if pending else "Still to do: nothing."])
    for item, details in pending:
        lines.append(f"  - {item}")
        lines.extend(f"      {detail}" for detail in details)
    lines.extend(["", "manual-checklist.md has the same lists, plus the source counts to compare."])
    return "\n".join(lines) + "\n"


def _pending(snapshot: dict[str, Any], report: ApplyReport) -> list[tuple[str, list[str]]]:
    """Each item is a sentence and the lines listed under it."""
    organization = snapshot.get("organization") or {}
    pending: list[tuple[str, list[str]]] = [(note, []) for note in report.notes]
    admins = team_admins_to_set(snapshot)
    if admins:
        pending.append(("After people accept their invites, run `org-copy update-team-admins` to make these team admins:", admins))
    if report.dropped_actions:
        pending.append(
            (
                "Recreate these alert actions once the integration is set up or the person has joined:",
                [f"{item.get('rule')}: {item.get('action')}" for item in report.dropped_actions],
            )
        )
    rejected = [f"org: {field}" for field in report.rejected_org_fields]
    rejected.extend(f"project {item.get('project')}: {item.get('field')}" for item in report.rejected_project_options)
    if rejected:
        pending.append(("Set these in the UI. The API did not accept them:", rejected))
    if organization.get("require2FA"):
        pending.append(("Turn on Require 2FA in the destination's security settings.", []))
    if organization.get("defaultRole") not in (None, "", "member"):
        pending.append((f"Set the default role to {organization['defaultRole']}. Tokens without org:admin can't change it.", []))
    if organization.get("hasAuthProvider") or snapshot.get("authProvider"):
        pending.append(("Set up SSO again. The IdP app needs the new org's ACS and SCIM endpoints.", []))
    integrations = [f"{item.get('provider') or item.get('name')}: {item.get('name')}" for item in snapshot.get("integrations") or []]
    if integrations:
        pending.append(("Reconnect these integrations:", integrations))
    apps = [str(item.get("app")) for item in snapshot.get("sentryAppInstallations") or []]
    if apps:
        pending.append(("Reinstall these Sentry apps:", apps))
    if report.dsn_map:
        pending.append(
            (
                "Once alerts work in the destination, point your SDKs at the new DSNs:",
                [f"{item.get('project')} / {item.get('key')}: {item.get('dsn')}" for item in report.dsn_map],
            )
        )
    return pending
