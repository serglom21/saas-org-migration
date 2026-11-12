"""Command line for export, plan, and apply."""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from org_copy import session
from org_copy.apply import ApplyOptions, apply_snapshot
from org_copy.checkpoint import render_checkpoint
from org_copy.checklist import render_checklist
from org_copy.client import ApiError, SentryClient
from org_copy.export import export_snapshot
from org_copy.files import load_state, read_json, write_json, write_text
from org_copy.redact import error_text
from org_copy.summary import render_summary
from org_copy.team_admins import update_team_admins


SOURCE_HOST = "https://us.sentry.io"
DEST_HOST = "https://de.sentry.io"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="org-copy",
        description=(
            "Copy Sentry organization settings from one region to another. "
            "Run without a command to be guided through the whole migration."
        ),
    )
    sub = parser.add_subparsers(dest="command")

    export = sub.add_parser("export", help="Read the source org into snapshot.json")
    _source_args(export)
    export.add_argument("--snapshot", default="snapshot.json")
    export.add_argument("--checklist", default="manual-checklist.md")

    plan = sub.add_parser("plan", help="Show what apply would change. No writes.")
    _dest_args(plan)
    plan.add_argument("--snapshot", default="snapshot.json")
    plan.add_argument("--state", default="state.json")
    _copy_flags(plan)

    apply = sub.add_parser("apply", help="Write settings onto the destination org")
    _dest_args(apply)
    apply.add_argument("--snapshot", default="snapshot.json")
    apply.add_argument("--state", default="state.json")
    apply.add_argument("--checklist", default="manual-checklist.md")
    apply.add_argument("--dsn-map", default="dsn-map.json")
    _copy_flags(apply)

    team_admins = sub.add_parser(
        "update-team-admins",
        help="Make org members team admins where they were in the source. Run after invites are accepted.",
    )
    _dest_args(team_admins)
    team_admins.add_argument("--snapshot", default="snapshot.json")

    args = parser.parse_args(argv)
    try:
        if args.command is None:
            return _guided()
        if args.command == "export":
            return _export(args, *_org_and_token("SOURCE", "Source"))
        org, token = _org_and_token("DEST", "Destination")
        if args.command == "plan":
            return _plan(args, org, token)
        if args.command == "update-team-admins":
            return _update_team_admins(args, org, token)
        return _apply(args, org, token)
    except ApiError as exc:
        print(error_text(exc), file=sys.stderr)
        return 1


def _source_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source-host", default=SOURCE_HOST)


def _dest_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dest-host", default=DEST_HOST)


def _copy_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--send-invites", action="store_true")
    parser.add_argument("--include-forwarders", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--hide-environments", action="store_true")
    parser.add_argument("--apply-replay-access", action="store_true")


def _guided() -> int:
    """Ask for both orgs, then plan or run the whole migration."""
    if not sys.stdin.isatty():
        raise SystemExit("org-copy asks for both orgs at startup. Run it in a terminal.")
    source_host = _ask_host("Source", SOURCE_HOST)
    source_org, source_token = _org_and_token("SOURCE", "Source")
    dest_host = _ask_host("Destination", DEST_HOST)
    dest_org, dest_token = _org_and_token("DEST", "Destination")
    print(
        "\nWhat do you want to do?\n"
        f"  1. Start migration: copy {source_org} to {dest_org} from start to finish.\n"
        f"  2. Plan: show what would be copied. Nothing is written to {dest_org}.",
        file=sys.stderr,
    )
    choice = ""
    while choice not in ("1", "2"):
        choice = input("Choose 1 or 2: ").strip()
    args = argparse.Namespace(
        source_host=source_host,
        dest_host=dest_host,
        snapshot="snapshot.json",
        checklist="manual-checklist.md",
        state="state.json",
        dsn_map="dsn-map.json",
        send_invites=False,
        include_forwarders=True,
        hide_environments=False,
        apply_replay_access=False,
    )
    print(file=sys.stderr)
    if _export(args, source_org, source_token) != 0 and not _confirm("Some settings could not be read. Continue?"):
        return 1
    print(file=sys.stderr)
    planned = _plan(args, dest_org, dest_token)
    if choice == "2":
        print(f"\nPlan only. Nothing was written to {dest_org}. Details are in {args.checklist}.", file=sys.stderr)
        return planned
    args.send_invites = _confirm("Email invites to the source members now?")
    if not _confirm(f"Do the numbers above look right? Write the changes to {dest_org}?"):
        print(f"Stopped. Nothing was written to {dest_org}.", file=sys.stderr)
        return 1
    print(file=sys.stderr)
    code = _apply(args, dest_org, dest_token)
    return code


def _ask_host(label: str, default: str) -> str:
    return input(f"{label} host [{default}]: ").strip() or default


def _confirm(question: str) -> bool:
    return input(f"{question} [y/N]: ").strip().lower() in ("y", "yes")


def _org_and_token(prefix: str, label: str) -> tuple[str, str]:
    """Ask for {prefix}_ORG and {prefix}_TOKEN, or offer the ones entered earlier in this terminal.

    Values already in the environment are ignored and removed, so a run never
    reuses an org or token left over from another shell.
    """
    stale = [name for name in (f"{prefix}_ORG", f"{prefix}_TOKEN") if os.environ.pop(name, None) is not None]
    if stale:
        print(f"Ignoring {' and '.join(stale)} from the environment.", file=sys.stderr)
    saved = session.remembered(prefix)
    if saved is not None and sys.stdin.isatty():
        org, token = saved
        answer = input(f"{label} org {org}, token {session.masked(token)}. Use them again? [Y/n]: ")
        if answer.strip().lower() in ("", "y", "yes"):
            return saved
    org = _ask(f"{label} org slug: ", f"{prefix}_ORG", secret=False)
    token = _ask(f"{label} token: ", f"{prefix}_TOKEN", secret=True)
    session.remember(prefix, org, token)
    return org, token


def _ask(prompt: str, name: str, *, secret: bool) -> str:
    if not sys.stdin.isatty():
        raise SystemExit(f"{name} is asked for at startup. Run org-copy in a terminal.")
    value = (getpass.getpass(prompt) if secret else input(prompt)).strip()
    if not value:
        raise SystemExit(f"Missing {name}.")
    return value


def _export(args: argparse.Namespace, org: str, token: str) -> int:
    with SentryClient(args.source_host, token, org) as client:
        snapshot = export_snapshot(client)
    write_json(args.snapshot, snapshot, secret=True)
    checklist = render_checklist(snapshot)
    write_text(args.checklist, checklist, secret=True)
    print(f"Wrote {args.snapshot} and {args.checklist}", file=sys.stderr)
    if snapshot.get("exportErrors"):
        print(f"{len(snapshot['exportErrors'])} export error(s). See the checklist.", file=sys.stderr)
        return 1
    return 0


def _options(args: argparse.Namespace, dry_run: bool) -> ApplyOptions:
    return ApplyOptions(
        dry_run=dry_run,
        send_invites=args.send_invites,
        include_forwarders=args.include_forwarders,
        hide_environments=args.hide_environments,
        apply_replay_access=args.apply_replay_access,
    )


def _plan(args: argparse.Namespace, org: str, token: str) -> int:
    snapshot = read_json(args.snapshot)
    with SentryClient(args.dest_host, token, org) as client:
        report = apply_snapshot(snapshot, client, load_state(args.state), args.state, _options(args, True))
    for action in report.actions:
        print(action)
    for note in report.notes:
        print(f"note: {note}")
    for failure in report.failures:
        print(f"fail: {failure['step']}: {failure['detail']}", file=sys.stderr)
    source_org = (snapshot.get("source") or {}).get("org") or "Source"
    print("\n" + render_checkpoint(snapshot, report, source_org, org), file=sys.stderr, end="")
    return 0 if report.ok else 1


def _apply(args: argparse.Namespace, org: str, token: str) -> int:
    snapshot = read_json(args.snapshot)
    state = load_state(args.state)
    with SentryClient(args.dest_host, token, org) as client:
        report = apply_snapshot(snapshot, client, state, args.state, _options(args, False))
    write_json(args.dsn_map, report.dsn_map, secret=True)
    checklist = render_checklist(
        snapshot,
        dest_org=org,
        actions=report.actions,
        failures=report.failures,
        dropped_actions=report.dropped_actions,
        dsn_map=report.dsn_map,
        rejected_org_fields=report.rejected_org_fields,
        rejected_project_options=report.rejected_project_options,
        notes=report.notes,
    )
    write_text(args.checklist, checklist, secret=True)
    for action in report.actions:
        print(action)
    print("\n" + render_summary(snapshot, report, org), file=sys.stderr, end="")
    return 0 if report.ok else 1


def _update_team_admins(args: argparse.Namespace, org: str, token: str) -> int:
    snapshot = read_json(args.snapshot)
    with SentryClient(args.dest_host, token, org) as client:
        report = update_team_admins(snapshot, client)
    for action in report.actions:
        print(action)
    for failure in report.failures:
        print(f"fail: {failure['step']}: {failure['detail']}", file=sys.stderr)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
