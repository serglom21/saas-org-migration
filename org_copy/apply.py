"""Create destination resources from a snapshot."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from org_copy.client import ApiError, SentryClient
from org_copy.export import ALL_PROJECTS
from org_copy.files import write_json
from org_copy.progress import Progress
from org_copy.redact import error_text
from org_copy.remap import (
    PROJECT_OPTION_KEYS,
    build_user_map,
    dashboard_body,
    detector_create_body,
    explore_query_body,
    fields_to_drop,
    issue_view_body,
    member_email,
    optional_org_body,
    org_settings_body,
    project_settings_body,
    public_key_settings,
    remap_owner,
    saved_query_body,
    uptime_detector_body,
    workflow_create_body,
)

LIST_PARAMS = {"per_page": "100"}
CREATED_DETECTOR_TYPES = {
    "metric_issue": detector_create_body,
    "uptime_domain_failure": uptime_detector_body,
}
CRON_DETECTOR_TYPE = "monitor_check_in_failure"
# Sections apply_snapshot always runs, including Reading the destination. The tests check [13/13].
APPLY_SECTIONS = 12


@dataclass
class ApplyOptions:
    dry_run: bool = False
    send_invites: bool = False
    include_forwarders: bool = True
    hide_environments: bool = False
    apply_replay_access: bool = False


@dataclass
class SectionResult:
    label: str
    # What the section did, such as "30 created, 120 related changes".
    summary: str
    actions: list[str] = field(default_factory=list)
    failures: list[dict[str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class ObjectKind:
    """One kind of object, such as projects, for counting a section by object."""

    label: str
    section: str
    # How the Sink summaries and failure steps for this kind start.
    prefixes: tuple[str, ...]
    count: Callable[[dict[str, Any]], int]
    # How apply decides that the destination already has one.
    match: str


def _count(key: str) -> Callable[[dict[str, Any]], int]:
    return lambda snapshot: len(snapshot.get(key) or [])


OBJECT_KINDS = (
    ObjectKind("Teams", "Teams", ("team ",), _count("teams"), "same slug"),
    ObjectKind("Projects", "Projects", ("project ",), _count("projects"), "same slug, its settings are updated"),
    ObjectKind("Data forwarders", "Data forwarders", ("forwarder ",), _count("forwarders"), "same provider, updated"),
    ObjectKind("Cron monitors", "Cron monitors", ("cron monitor ",), _count("monitors"), "same slug"),
    ObjectKind(
        "Monitors",
        "Monitors",
        ("detector ",),
        lambda snapshot: len(_iter_detectors(snapshot)),
        "same name in the same project",
    ),
    ObjectKind("Alerts", "Alerts", ("workflow ",), _count("workflows"), "same name and monitors"),
    ObjectKind("Dashboards", "Dashboards", ("dashboard ",), _count("dashboards"), "same title"),
    ObjectKind("Saved queries", "Saved queries", ("saved query ",), _count("savedQueries"), "same name"),
    ObjectKind("Explore saved queries", "Saved queries", ("explore query ",), _count("exploreQueries"), "same name"),
    ObjectKind(
        "Issue views",
        "Issue views",
        ("issue view ",),
        lambda snapshot: len(_issue_views(snapshot)),
        "same name and query",
    ),
)


@dataclass
class ApplyReport:
    actions: list[str] = field(default_factory=list)
    failures: list[dict[str, str]] = field(default_factory=list)
    dropped_actions: list[dict[str, str]] = field(default_factory=list)
    dsn_map: list[dict[str, str]] = field(default_factory=list)
    rejected_org_fields: list[str] = field(default_factory=list)
    rejected_project_options: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    sections: list[SectionResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures


class Sink:
    def __init__(self, client: SentryClient, report: ApplyReport, dry_run: bool):
        self.client = client
        self.report = report
        self.dry_run = dry_run
        self._seq = 0
        # Summaries created in this run, to tell duplicates in the source from objects already there.
        self._created: set[str] = set()

    def post(self, path: str, body: dict[str, Any], summary: str) -> dict[str, Any]:
        self._created.add(summary)
        if self.dry_run:
            self.report.actions.append(f"create {summary}")
            self._seq += 1
            echoed: dict[str, Any] = {
                "id": f"plan-{self._seq}",
                "slug": body.get("slug") or body.get("name") or body.get("title"),
                "name": body.get("name") or body.get("title"),
            }
            if path.endswith("/keys/"):
                echoed["dsn"] = {"public": "<assigned on apply>"}
            return echoed
        result = self.client.post(path, json=body)
        self.report.actions.append(f"created {summary}")
        return result if isinstance(result, dict) else {}

    def put(self, path: str, body: dict[str, Any], summary: str) -> Any:
        if self.dry_run:
            self.report.actions.append(f"update {summary}")
            return body
        result = self.client.put(path, json=body)
        self.report.actions.append(f"updated {summary}")
        return result

    def skip(self, summary: str, not_copied: str | None = None) -> None:
        """Record an object that is not created: already in the destination, or not copied for a reason."""
        if not_copied is None and summary in self._created:
            not_copied = "duplicate of another in the source"
        if not_copied:
            summary += f"{NOT_COPIED_START}{not_copied})"
        self.report.actions.append(f"skip {summary}")


def apply_snapshot(
    snapshot: dict[str, Any],
    client: SentryClient,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
) -> ApplyReport:
    report = ApplyReport()
    sink = Sink(client, report, options.dry_run)
    title = f"Comparing with {client.org}. Nothing is written yet." if options.dry_run else f"Writing to {client.org}"
    optional = (options.send_invites, options.hide_environments, options.apply_replay_access)
    progress = Progress(title, APPLY_SECTIONS + sum(optional))
    with progress.section("Reading the destination") as summary:
        dest = _DestIndex.load(client, report)
        if dest is None:
            summary.append("failed")
    if dest is None:
        return report
    user_map = build_user_map(snapshot.get("members") or [], dest.members)
    team_map: dict[str, str] = {}
    project_map: dict[str, str] = {}
    detector_map: dict[str, str] = {}

    with _section(progress, report, "Organization settings"):
        _apply_org(snapshot, sink, dest, report)
    with _section(progress, report, "Teams"):
        _apply_teams(snapshot, sink, dest, state, state_path, options, team_map)
    with _section(progress, report, "Team memberships"):
        _apply_existing_member_teams(snapshot, sink, dest, report)
    with _section(progress, report, "Projects"):
        _apply_projects(snapshot, client, sink, dest, state, state_path, options, report, team_map, project_map, progress)
    with _section(progress, report, "Data forwarders"):
        _apply_forwarders(snapshot, sink, dest, state, state_path, options, project_map, report)
    with _section(progress, report, "Cron monitors"):
        _apply_monitors(snapshot, sink, dest, state, state_path, options, team_map, user_map, project_map, report, progress)
    with _section(progress, report, "Monitors"):
        # New projects and cron monitors get their own detectors. Alerts connect to those.
        dest.load_detectors(client, report)
        _apply_detectors(
            snapshot, sink, dest, state, state_path, options, team_map, user_map, project_map, detector_map, report, progress
        )
    with _section(progress, report, "Alerts"):
        _apply_workflows(snapshot, sink, dest, state, state_path, options, team_map, user_map, detector_map, report, progress)
    with _section(progress, report, "Dashboards"):
        _apply_dashboards(snapshot, sink, dest, state, state_path, options, team_map, project_map, report, progress)
    with _section(progress, report, "Saved queries"):
        _apply_queries(snapshot, sink, dest, state, state_path, options, project_map, report)
        _apply_explore_queries(snapshot, sink, dest, state, state_path, options, project_map, report)
    with _section(progress, report, "Issue views"):
        _apply_views(snapshot, sink, dest, state, state_path, options, project_map, report)
    if options.send_invites:
        with _section(progress, report, "Invites"):
            _apply_invites(snapshot, sink, dest, report)
    else:
        report.notes.append(
            "Member invites were not sent. Run org-copy again and answer y when it asks about invites, "
            "or run `org-copy apply --send-invites`."
        )
    if options.hide_environments:
        with _section(progress, report, "Hidden environments"):
            _apply_hidden_environments(snapshot, sink, report)
    if options.apply_replay_access:
        with _section(progress, report, "Replay access"):
            _apply_replay(snapshot, sink, dest, report)
    return report


@contextmanager
def _section(progress: Progress, report: ApplyReport, label: str) -> Iterator[None]:
    """Run one apply section and summarize the actions and failures it added."""
    start_actions, start_failures = len(report.actions), len(report.failures)
    with progress.section(label) as summary:
        yield
        actions = report.actions[start_actions:]
        failures = report.failures[start_failures:]
        summary.extend(_summarize_actions(actions, failures, _section_prefixes(label)))
        report.sections.append(SectionResult(label, ", ".join(summary), actions, failures))


def _section_prefixes(label: str) -> tuple[str, ...]:
    return tuple(prefix for kind in OBJECT_KINDS if kind.section == label for prefix in kind.prefixes)


# Marks a skip that is not copied, as in "skip dashboard Errors (not copied: prebuilt)".
NOT_COPIED_START = " (not copied: "


def action_outcome(action: str) -> str:
    """Name what an action does to its object: create, created, update, updated, existing, or not copied."""
    verb, _, rest = action.partition(" ")
    if verb != "skip":
        return verb
    return "not copied" if NOT_COPIED_START in rest else "existing"


# How each outcome reads in a section summary.
_SUMMARY_WORDS = {
    "create": "to create",
    "created": "created",
    "update": "to update",
    "updated": "updated",
    "existing": "already there",
    "not copied": "not copied",
}


def _summarize_actions(actions: list[str], failures: list[dict[str, str]], prefixes: tuple[str, ...]) -> list[str]:
    """Count the section's objects by outcome. Other actions, such as project keys, count as related changes."""
    outcomes: Counter[str] = Counter()
    related = 0
    for action in actions:
        if prefixes and not action.partition(" ")[2].startswith(prefixes):
            related += 1
        else:
            outcomes[action_outcome(action)] += 1
    summary = [f"{count} {_SUMMARY_WORDS.get(outcome, outcome)}" for outcome, count in outcomes.items()]
    if related:
        summary.append(f"{related} related changes")
    if failures:
        summary.append(f"{len(failures)} failed")
    return summary or ["nothing to copy"]


class _DestIndex:
    def __init__(self) -> None:
        self.org: dict[str, Any] = {}
        self.teams_by_slug: dict[str, dict[str, Any]] = {}
        self.projects_by_slug: dict[str, dict[str, Any]] = {}
        self.members: list[dict[str, Any]] = []
        self.members_by_email: dict[str, dict[str, Any]] = {}
        self.workflow_keys: set[tuple[str, tuple[str, ...]]] = set()
        self.monitors_by_slug: dict[str, dict[str, Any]] = {}
        self.dashboards_by_title: dict[str, dict[str, Any]] = {}
        self.queries_by_name: dict[str, dict[str, Any]] = {}
        self.explore_queries_by_name: dict[str, dict[str, Any]] = {}
        self.view_keys: set[tuple[str, str]] = set()
        self.forwarders_by_provider: dict[str, dict[str, Any]] = {}
        self.detectors: list[dict[str, Any]] = []
        self.detectors_by_key: dict[str, dict[str, Any]] = {}

    @classmethod
    def load(cls, client: SentryClient, report: ApplyReport) -> _DestIndex | None:
        index = cls()
        try:
            org = client.get_json(f"/organizations/{client.org}/")
        except ApiError as exc:
            report.failures.append({"step": "load destination org", "detail": error_text(exc)})
            return None
        if not isinstance(org, dict):
            report.failures.append({"step": "load destination org", "detail": "organization response was empty"})
            return None
        index.org = org
        index.teams_by_slug = _by(client, f"/organizations/{client.org}/teams/", "slug", report, "teams")
        index.projects_by_slug = _by(client, f"/organizations/{client.org}/projects/", "slug", report, "projects")
        members, error = client.get_optional_list(f"/organizations/{client.org}/members/", LIST_PARAMS)
        if error and error.status != 404:
            report.failures.append({"step": "list destination members", "detail": error_text(error)})
        index.members = members
        index.members_by_email = {member_email(member): member for member in members if member_email(member)}
        workflows, workflow_error = client.get_optional_list(f"/organizations/{client.org}/workflows/", ALL_PROJECTS)
        if workflow_error and workflow_error.status != 404:
            report.failures.append({"step": "list destination workflows", "detail": error_text(workflow_error)})
        index.workflow_keys = {
            _workflow_key(item["name"], item.get("detectorIds") or []) for item in workflows if item.get("name")
        }
        index.monitors_by_slug = _by(
            client, f"/organizations/{client.org}/monitors/", "slug", report, "monitors", ALL_PROJECTS
        )
        index.dashboards_by_title = _by(client, f"/organizations/{client.org}/dashboards/", "title", report, "dashboards")
        index.queries_by_name = _by(client, f"/organizations/{client.org}/discover/saved/", "name", report, "saved queries")
        index.explore_queries_by_name = _by(
            client, f"/organizations/{client.org}/explore/saved/", "name", report, "explore saved queries"
        )
        views, view_error = client.get_optional_list(
            f"/organizations/{client.org}/group-search-views/",
            {"createdBy": "me", **LIST_PARAMS},
        )
        if view_error and view_error.status != 404:
            report.failures.append({"step": "list destination issue views", "detail": error_text(view_error)})
        index.view_keys = {_view_key(item) for item in views if item.get("name")}
        forwarders, forward_error = client.get_optional_list(f"/organizations/{client.org}/forwarding/")
        if forward_error and forward_error.status != 404:
            report.failures.append({"step": "list destination forwarders", "detail": error_text(forward_error)})
        index.forwarders_by_provider = {item.get("provider"): item for item in forwarders if item.get("provider")}
        return index

    def load_detectors(self, client: SentryClient, report: ApplyReport) -> None:
        detectors, error = client.get_optional_list(f"/organizations/{client.org}/detectors/", ALL_PROJECTS)
        if error and error.status != 404:
            report.failures.append({"step": "list destination detectors", "detail": error_text(error)})
        self.detectors = detectors
        self.detectors_by_key = {}
        for detector in detectors:
            project_id = str(detector.get("projectId") or "")
            name = detector.get("name")
            if project_id and name:
                self.detectors_by_key[f"{project_id}:{name}"] = detector


def _workflow_key(name: str, detector_ids: list[Any]) -> tuple[str, tuple[str, ...]]:
    """Alerts share names across projects, so an alert is the same only when it watches the same monitors."""
    return name, tuple(sorted(str(detector_id) for detector_id in detector_ids))


def _by(
    client: SentryClient,
    path: str,
    key: str,
    report: ApplyReport,
    label: str,
    params: dict[str, str] = LIST_PARAMS,
) -> dict[str, dict[str, Any]]:
    rows, error = client.get_optional_list(path, params)
    if error and error.status != 404:
        report.failures.append({"step": f"list destination {label}", "detail": error_text(error)})
    return {row[key]: row for row in rows if isinstance(row, dict) and row.get(key)}


def _remember(state: dict[str, Any], bucket: str, source_id: Any, dest_id: Any, path: str, dry_run: bool) -> None:
    if dry_run or source_id in (None, "") or dest_id in (None, ""):
        return
    state.setdefault(bucket, {})[str(source_id)] = str(dest_id)
    write_json(path, state, secret=True)


def _fail(report: ApplyReport, step: str, exc: Exception) -> None:
    report.failures.append({"step": step, "detail": error_text(exc)})


def _put_dropping(sink: Sink, path: str, body: dict[str, Any], summary: str) -> tuple[Any, list[str]]:
    if sink.dry_run:
        sink.put(path, body, summary)
        return body, []
    current = dict(body)
    dropped: list[str] = []
    for _ in range(12):
        try:
            result = sink.client.put(path, json=current)
            sink.report.actions.append(f"updated {summary}")
            return result, dropped
        except ApiError as exc:
            keys = fields_to_drop(exc.body, current)
            if exc.status != 400 or not keys:
                raise
            for key in keys:
                dropped.append(key)
                current.pop(key, None)
            if not current:
                raise
    raise ApiError("PUT", path, 400, {"detail": "too many rejected fields"})


def _apply_org(snapshot: dict[str, Any], sink: Sink, dest: _DestIndex, report: ApplyReport) -> None:
    organization = snapshot.get("organization") or {}
    body = org_settings_body(organization)
    if not body:
        sink.skip("org settings", "nothing to copy")
        return
    try:
        _result, dropped = _put_dropping(sink, f"/organizations/{sink.client.org}/", body, "org settings")
        report.rejected_org_fields.extend(dropped)
    except ApiError as exc:
        _fail(report, "org settings", exc)
    for field, value in optional_org_body(organization).items():
        try:
            sink.put(f"/organizations/{sink.client.org}/", {field: value}, f"org {field}")
        except ApiError as exc:
            if exc.status == 400:
                report.rejected_org_fields.append(field)
            else:
                _fail(report, f"org {field}", exc)


def _apply_teams(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    team_map: dict[str, str],
) -> None:
    org = sink.client.org
    for team in snapshot.get("teams") or []:
        slug = team.get("slug")
        if not slug:
            continue
        existing = dest.teams_by_slug.get(slug)
        if existing:
            team_map[str(team.get("id"))] = str(existing.get("id"))
            wanted = team.get("name") or slug
            if existing.get("name") != wanted:
                try:
                    sink.put(f"/teams/{org}/{slug}/", {"name": wanted}, f"team name {slug}")
                except ApiError as exc:
                    _fail(sink.report, f"team name {slug}", exc)
            else:
                sink.skip(f"team {slug}")
            continue
        try:
            created = sink.post(
                f"/organizations/{org}/teams/",
                {"name": team.get("name") or slug, "slug": slug},
                f"team {slug}",
            )
        except ApiError as exc:
            _fail(sink.report, f"team {slug}", exc)
            continue
        dest_id = str(created.get("id"))
        team_map[str(team.get("id"))] = dest_id
        dest.teams_by_slug[slug] = created
        _remember(state, "teams", team.get("id"), dest_id, state_path, options.dry_run)


def _apply_existing_member_teams(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    report: ApplyReport,
) -> None:
    """Add people who already belong to the destination org onto the copied teams."""
    org = sink.client.org
    for member in snapshot.get("members") or []:
        email = member_email(member)
        dest_member = dest.members_by_email.get(email)
        if not email or not dest_member or dest_member.get("pending"):
            continue
        member_id = dest_member.get("id")
        if not member_id:
            continue
        current = set()
        for item in dest_member.get("teamSlugs") or dest_member.get("teams") or []:
            if isinstance(item, str):
                current.add(item)
            elif isinstance(item, dict) and item.get("slug"):
                current.add(item["slug"])
        for slug in member.get("teamSlugs") or []:
            if slug in current or slug not in dest.teams_by_slug:
                continue
            try:
                sink.post(
                    f"/organizations/{org}/members/{member_id}/teams/{slug}/",
                    {},
                    f"team membership {email} on {slug}",
                )
            except ApiError as exc:
                _fail(report, f"team membership {email} on {slug}", exc)
                continue
            current.add(slug)
            dest_member.setdefault("teamSlugs", []).append(slug)


def _apply_projects(
    snapshot: dict[str, Any],
    client: SentryClient,
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    report: ApplyReport,
    team_map: dict[str, str],
    project_map: dict[str, str],
    progress: Progress,
) -> None:
    org = client.org
    for project in progress.items(snapshot.get("projects") or []):
        slug = project.get("slug")
        if not slug:
            continue
        existing = dest.projects_by_slug.get(slug)
        if existing:
            sink.skip(f"project {slug}")
            created = existing
        else:
            team_slug = _primary_team_slug(project)
            if not team_slug:
                report.failures.append({"step": f"project {slug}", "detail": "project has no team"})
                continue
            body: dict[str, Any] = {
                "name": project.get("name") or slug,
                "slug": slug,
                "default_rules": False,
            }
            if project.get("platform"):
                body["platform"] = project["platform"]
            try:
                created = sink.post(f"/teams/{org}/{team_slug}/projects/", body, f"project {slug}")
            except ApiError as exc:
                _fail(report, f"project {slug}", exc)
                continue
            dest.projects_by_slug[slug] = created
        dest_id = str(created.get("id"))
        project_map[str(project.get("id"))] = dest_id
        _remember(state, "projects", project.get("id"), dest_id, state_path, options.dry_run)
        _attach_extra_teams(project, sink, org, slug, report)
        _apply_project_settings(project, sink, org, report)
        _apply_filters(project, sink, org, report)
        _apply_ownership(project, sink, org, report)
        _apply_keys(project, client, sink, org, report, options)


def _primary_team_slug(project: dict[str, Any]) -> str | None:
    detail = project.get("detail") or {}
    team = detail.get("team") if isinstance(detail.get("team"), dict) else None
    if team and team.get("slug"):
        return team["slug"]
    teams = project.get("teams") or []
    if teams:
        return teams[0].get("slug")
    return None


def _attach_extra_teams(project: dict[str, Any], sink: Sink, org: str, slug: str, report: ApplyReport) -> None:
    primary = _primary_team_slug(project)
    for team in project.get("teams") or []:
        team_slug = team.get("slug")
        if not team_slug or team_slug == primary:
            continue
        try:
            sink.post(f"/projects/{org}/{slug}/teams/{team_slug}/", {}, f"team {team_slug} on {slug}")
        except ApiError as exc:
            if exc.status == 409:
                sink.skip(f"team {team_slug} on {slug}")
            else:
                _fail(report, f"team {team_slug} on {slug}", exc)


def _apply_project_settings(project: dict[str, Any], sink: Sink, org: str, report: ApplyReport) -> None:
    detail = project.get("detail") or {}
    body = project_settings_body(detail)
    if not body:
        return
    slug = project["slug"]
    try:
        _result, dropped = _put_dropping(sink, f"/projects/{org}/{slug}/", body, f"settings on {slug}")
    except ApiError as exc:
        _fail(report, f"settings on {slug}", exc)
        return
    for field in dropped:
        if field in PROJECT_OPTION_KEYS or field in body:
            report.rejected_project_options.append({"project": slug, "field": field})


def _apply_filters(project: dict[str, Any], sink: Sink, org: str, report: ApplyReport) -> None:
    slug = project["slug"]
    for item in project.get("filters") or []:
        filter_id = item.get("id")
        if not filter_id:
            continue
        if isinstance(item.get("active"), list):
            body: dict[str, Any] = {"subfilters": item["active"]}
            candidates = [filter_id]
            if filter_id == "legacy-browsers":
                candidates.append("legacy-browser")
        else:
            body = {"active": bool(item.get("active"))}
            candidates = [filter_id]
        last_error: ApiError | None = None
        for candidate in candidates:
            try:
                sink.put(
                    f"/projects/{org}/{slug}/filters/{candidate}/",
                    body,
                    f"filter {filter_id} on {slug}",
                )
                last_error = None
                break
            except ApiError as exc:
                last_error = exc
                if exc.status != 404:
                    break
        if last_error is not None:
            _fail(report, f"filter {filter_id} on {slug}", last_error)


def _apply_ownership(project: dict[str, Any], sink: Sink, org: str, report: ApplyReport) -> None:
    ownership = project.get("ownership")
    if not isinstance(ownership, dict):
        return
    slug = project["slug"]
    body = {
        "raw": ownership.get("raw") or "",
        "fallthrough": ownership.get("fallthrough", True),
        "autoAssignment": ownership.get("autoAssignment"),
        "codeownersAutoSync": False,
    }
    try:
        sink.put(f"/projects/{org}/{slug}/ownership/", body, f"ownership on {slug}")
    except ApiError as exc:
        _fail(report, f"ownership on {slug}", exc)


def _apply_keys(
    project: dict[str, Any],
    client: SentryClient,
    sink: Sink,
    org: str,
    report: ApplyReport,
    options: ApplyOptions,
) -> None:
    slug = project["slug"]
    source_keys = project.get("keys") or []
    if not source_keys:
        return
    dest_keys: list[dict[str, Any]] = []
    try:
        dest_keys = client.get_all(f"/projects/{org}/{slug}/keys/")
    except ApiError as exc:
        if exc.status != 404:
            _fail(report, f"keys on {slug}", exc)
            return
    unused = list(dest_keys)
    for source in source_keys:
        settings = public_key_settings(source)
        name = settings["name"]
        match = next((key for key in unused if (key.get("name") or key.get("label")) == name), None)
        if match is None and unused:
            match = unused[0]
        if match is not None:
            unused.remove(match)
            try:
                updated = sink.put(
                    f"/projects/{org}/{slug}/keys/{match.get('id')}/",
                    settings,
                    f"key {name} on {slug}",
                )
            except ApiError as exc:
                _fail(report, f"key {name} on {slug}", exc)
                continue
            dsn = _public_dsn(updated) or _public_dsn(match)
        else:
            try:
                created = sink.post(f"/projects/{org}/{slug}/keys/", {"name": name}, f"key {name} on {slug}")
                updated = sink.put(
                    f"/projects/{org}/{slug}/keys/{created.get('id')}/",
                    settings,
                    f"key settings {name} on {slug}",
                )
            except ApiError as exc:
                _fail(report, f"key {name} on {slug}", exc)
                continue
            dsn = _public_dsn(updated) or _public_dsn(created)
        report.dsn_map.append({"project": slug, "key": name, "dsn": dsn or "<assigned on apply>"})


def _public_dsn(key: Any) -> str | None:
    if not isinstance(key, dict):
        return None
    dsn = key.get("dsn")
    if isinstance(dsn, dict):
        return dsn.get("public")
    return None


def _apply_forwarders(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    project_map: dict[str, str],
    report: ApplyReport,
) -> None:
    if not options.include_forwarders:
        report.notes.append("Data forwarders were not copied. Re-run apply with --include-forwarders.")
        return
    org = sink.client.org
    org_id = dest.org.get("id")
    for forwarder in snapshot.get("forwarders") or []:
        provider = forwarder.get("provider")
        if not provider:
            continue
        project_ids = []
        for project in forwarder.get("enrolledProjects") or []:
            if not isinstance(project, dict):
                continue
            dest_id = project_map.get(str(project.get("id")))
            if dest_id and str(dest_id).isdigit():
                project_ids.append(int(dest_id))
        body = {
            "organization_id": int(org_id) if str(org_id).isdigit() else org_id,
            "provider": provider,
            "is_enabled": forwarder.get("isEnabled", True),
            "enroll_new_projects": forwarder.get("enrollNewProjects", False),
            "config": forwarder.get("config") or {},
            "project_ids": project_ids,
        }
        existing = dest.forwarders_by_provider.get(provider)
        try:
            if existing:
                sink.put(
                    f"/organizations/{org}/forwarding/{existing.get('id')}/",
                    body,
                    f"forwarder {provider}",
                )
                dest_id = existing.get("id")
            else:
                created = sink.post(f"/organizations/{org}/forwarding/", body, f"forwarder {provider}")
                dest_id = created.get("id")
                dest.forwarders_by_provider[provider] = created
        except ApiError as exc:
            _fail(report, f"forwarder {provider}", exc)
            continue
        _remember(state, "forwarders", forwarder.get("id"), dest_id, state_path, options.dry_run)


def _project_slug_for_detector(snapshot: dict[str, Any], detector: dict[str, Any]) -> str | None:
    project_id = str(detector.get("projectId") or "")
    for project in snapshot.get("projects") or []:
        if str(project.get("id")) == project_id:
            return project.get("slug")
        for owned in project.get("detectors") or []:
            if str(owned.get("id")) == str(detector.get("id")):
                return project.get("slug")
    return None


def _iter_detectors(snapshot: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    found: list[tuple[str, dict[str, Any]]] = []
    seen: set[str] = set()
    for project in snapshot.get("projects") or []:
        for detector in project.get("detectors") or []:
            ident = str(detector.get("id") or "") + ":" + str(detector.get("name"))
            if ident in seen:
                continue
            seen.add(ident)
            found.append((project.get("slug"), detector))
    found.extend(("the organization", detector) for detector in snapshot.get("orgDetectors") or [])
    return found


def _cron_slug(detector: dict[str, Any]) -> str | None:
    for source in detector.get("dataSources") or []:
        query = source.get("queryObj") if isinstance(source, dict) else None
        if isinstance(query, dict) and query.get("slug"):
            return str(query["slug"])
    return None


def _existing_dest_detector(
    detector: dict[str, Any], dest: _DestIndex, project_map: dict[str, str]
) -> dict[str, Any] | None:
    """Find the destination detector that Sentry created for us: project defaults, cron monitors, all-projects."""
    kind = detector.get("type")
    candidates = [item for item in dest.detectors if item.get("type") == kind]
    if kind == CRON_DETECTOR_TYPE:
        slug = _cron_slug(detector)
        return next((item for item in candidates if slug and _cron_slug(item) == slug), None)
    if not detector.get("projectId"):
        return next((item for item in candidates if not item.get("projectId")), None)
    dest_project = project_map.get(str(detector["projectId"]))
    return next((item for item in candidates if dest_project and str(item.get("projectId")) == dest_project), None)


def _planned(detector: dict[str, Any], dest: _DestIndex, project_map: dict[str, str]) -> bool:
    """In a plan, projects and cron monitors are not created, so their detectors cannot be found yet."""
    if detector.get("type") == CRON_DETECTOR_TYPE:
        planned = dest.monitors_by_slug.get(_cron_slug(detector) or "")
        return bool(planned) and str(planned.get("id")).startswith("plan-")
    return str(project_map.get(str(detector.get("projectId") or ""), "")).startswith("plan-")


def _apply_detectors(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    team_map: dict[str, str],
    user_map: dict[str, str],
    project_map: dict[str, str],
    detector_map: dict[str, str],
    report: ApplyReport,
    progress: Progress,
) -> None:
    org = sink.client.org
    for slug, detector in progress.items(_iter_detectors(snapshot)):
        name = detector.get("name") or "monitor"
        kind = str(detector.get("type") or "")
        source_id = str(detector.get("id"))
        build_body = CREATED_DETECTOR_TYPES.get(kind)
        if build_body is None:
            existing = _existing_dest_detector(detector, dest, project_map)
            if existing:
                detector_map[source_id] = str(existing.get("id"))
                sink.skip(f"detector {name} on {slug}", "built in, the destination has its own")
            elif sink.dry_run and _planned(detector, dest, project_map):
                detector_map[source_id] = f"{kind} on {slug}"
                sink.skip(f"detector {name} on {slug}", "built in, the new project gets its own")
            else:
                report.failures.append(
                    {
                        "step": f"detector {name} ({kind}) on {slug}",
                        "detail": "no matching destination detector, so alerts connected to it were not copied",
                    }
                )
            continue
        dest_project = project_map.get(str(detector.get("projectId") or ""))
        existing = dest.detectors_by_key.get(f"{dest_project}:{name}") if dest_project else None
        if existing:
            sink.skip(f"detector {name} on {slug}")
            detector_map[source_id] = str(existing.get("id"))
            continue
        owner = remap_owner(detector.get("owner"), team_map, user_map)
        try:
            created = sink.post(
                f"/organizations/{org}/projects/{slug}/detectors/",
                build_body(detector, owner),
                f"detector {name} on {slug}",
            )
        except ApiError as exc:
            _fail(report, f"detector {name} on {slug}", exc)
            continue
        detector_map[source_id] = str(created.get("id"))
        _remember(state, "detectors", detector.get("id"), created.get("id"), state_path, options.dry_run)


def _apply_workflows(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    team_map: dict[str, str],
    user_map: dict[str, str],
    detector_map: dict[str, str],
    report: ApplyReport,
    progress: Progress,
) -> None:
    org = sink.client.org
    for workflow in progress.items(snapshot.get("workflows") or []):
        name = workflow.get("name")
        if not name:
            sink.skip("workflow ", "no name")
            continue
        unmapped = [str(item) for item in workflow.get("detectorIds") or [] if str(item) not in detector_map]
        if unmapped:
            report.failures.append(
                {
                    "step": f"workflow {name}",
                    "detail": f"connected detectors {', '.join(unmapped)} were not copied, so the alert was not created",
                }
            )
            continue
        owner = remap_owner(workflow.get("owner"), team_map, user_map)
        body, dropped = workflow_create_body(workflow, detector_map, owner, user_map, team_map)
        # List integration actions on every run so the checklist keeps them until they are set up by hand.
        for action in dropped:
            report.dropped_actions.append({"rule": name, "action": action})
        key = _workflow_key(name, body["detectorIds"])
        if key in dest.workflow_keys:
            sink.skip(f"workflow {name}")
            continue
        try:
            created = sink.post(f"/organizations/{org}/workflows/", body, f"workflow {name}")
        except ApiError as exc:
            _fail(report, f"workflow {name}", exc)
            continue
        dest.workflow_keys.add(key)
        _remember(state, "workflows", workflow.get("id"), created.get("id"), state_path, options.dry_run)


def _apply_monitors(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    team_map: dict[str, str],
    user_map: dict[str, str],
    project_map: dict[str, str],
    report: ApplyReport,
    progress: Progress,
) -> None:
    org = sink.client.org
    slug_by_id = {str(project.get("id")): project.get("slug") for project in snapshot.get("projects") or []}
    for monitor in progress.items(snapshot.get("monitors") or []):
        slug = monitor.get("slug")
        name = monitor.get("name") or slug
        if not slug:
            continue
        if dest.monitors_by_slug.get(slug):
            sink.skip(f"cron monitor {slug}")
            continue
        project_slug = monitor.get("project") or slug_by_id.get(str(monitor.get("projectId") or ""))
        if isinstance(project_slug, dict):
            project_slug = project_slug.get("slug")
        owner = remap_owner(monitor.get("owner"), team_map, user_map)
        body: dict[str, Any] = {
            "project": project_slug,
            "name": name,
            "slug": slug,
            "status": monitor.get("status") or "active",
            "config": monitor.get("config"),
            "is_muted": monitor.get("isMuted", monitor.get("is_muted", False)),
        }
        if owner:
            body["owner"] = owner
        try:
            created = sink.post(f"/organizations/{org}/monitors/", body, f"cron monitor {slug}")
        except ApiError as exc:
            _fail(report, f"cron monitor {slug}", exc)
            continue
        dest.monitors_by_slug[slug] = created
        _remember(state, "monitors", monitor.get("id"), created.get("id"), state_path, options.dry_run)


def _apply_dashboards(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    team_map: dict[str, str],
    project_map: dict[str, str],
    report: ApplyReport,
    progress: Progress,
) -> None:
    org = sink.client.org
    for dashboard in progress.items(snapshot.get("dashboards") or []):
        if dashboard.get("prebuiltId"):
            sink.skip(f"dashboard {dashboard.get('title')}", "prebuilt, the destination has its own")
            continue
        title = dashboard.get("title")
        if not title:
            continue
        if dest.dashboards_by_title.get(title):
            sink.skip(f"dashboard {title}")
            continue
        body = dashboard_body(dashboard, project_map, team_map)
        try:
            created = sink.post(f"/organizations/{org}/dashboards/", body, f"dashboard {title}")
        except ApiError as exc:
            _fail(report, f"dashboard {title}", exc)
            continue
        dest.dashboards_by_title[title] = created
        _remember(state, "dashboards", dashboard.get("id"), created.get("id"), state_path, options.dry_run)


def _apply_queries(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    project_map: dict[str, str],
    report: ApplyReport,
) -> None:
    org = sink.client.org
    for query in snapshot.get("savedQueries") or []:
        name = query.get("name")
        if not name:
            continue
        if dest.queries_by_name.get(name):
            sink.skip(f"saved query {name}")
            continue
        try:
            created = sink.post(
                f"/organizations/{org}/discover/saved/",
                saved_query_body(query, project_map),
                f"saved query {name}",
            )
        except ApiError as exc:
            _fail(report, f"saved query {name}", exc)
            continue
        dest.queries_by_name[name] = created
        _remember(state, "queries", query.get("id"), created.get("id"), state_path, options.dry_run)


def _apply_explore_queries(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    project_map: dict[str, str],
    report: ApplyReport,
) -> None:
    org = sink.client.org
    for query in snapshot.get("exploreQueries") or []:
        name = query.get("name")
        if not name:
            continue
        if query.get("isPrebuilt"):
            sink.skip(f"explore query {name}", "prebuilt, the destination has its own")
            continue
        if dest.explore_queries_by_name.get(name):
            sink.skip(f"explore query {name}")
            continue
        try:
            created = sink.post(
                f"/organizations/{org}/explore/saved/",
                explore_query_body(query, project_map),
                f"explore query {name}",
            )
        except ApiError as exc:
            _fail(report, f"explore query {name}", exc)
            continue
        dest.explore_queries_by_name[name] = created
        _remember(state, "exploreQueries", query.get("id"), created.get("id"), state_path, options.dry_run)


def _apply_views(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    project_map: dict[str, str],
    report: ApplyReport,
) -> None:
    """Copy the token user's views and the views other members share with the organization.

    The destination creates them all as the token user's, shared with the organization.
    """
    org = sink.client.org
    mine = (snapshot.get("issueViews") or {}).get("mine") or []
    for view in _issue_views(snapshot):
        name = view.get("name")
        if not name:
            continue
        if _view_key(view) in dest.view_keys:
            sink.skip(f"issue view {name}")
            continue
        body = issue_view_body(view, project_map)
        # Starring belongs to the person who starred it, so only the token user's own views keep it.
        body["starred"] = body["starred"] and view in mine
        try:
            created = sink.post(f"/organizations/{org}/group-search-views/", body, f"issue view {name}")
        except ApiError as exc:
            _fail(report, f"issue view {name}", exc)
            continue
        dest.view_keys.add(_view_key(view))
        _remember(state, "views", view.get("id"), created.get("id"), state_path, options.dry_run)


def _issue_views(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    views = snapshot.get("issueViews") or {}
    return [*(views.get("mine") or []), *(views.get("others") or [])]


def _view_key(view: dict[str, Any]) -> tuple[str, str]:
    """Members often reuse view names, so a view is the same only when its query matches too."""
    return str(view.get("name")), str(view.get("query") or "")


def _apply_invites(snapshot: dict[str, Any], sink: Sink, dest: _DestIndex, report: ApplyReport) -> None:
    org = sink.client.org
    for member in snapshot.get("members") or []:
        email = member_email(member)
        if not email:
            continue
        if email in dest.members_by_email:
            sink.skip(f"invite {email}")
            continue
        body: dict[str, Any] = {
            "email": email,
            "role": member.get("orgRole") or "member",
            "teams": member.get("teamSlugs") or [],
            "sendInvite": True,
        }
        if member.get("teamRoles"):
            body["teamRoles"] = member["teamRoles"]
        try:
            sink.post(f"/organizations/{org}/members/", body, f"invite {email}")
        except ApiError as exc:
            _fail(report, f"invite {email}", exc)


def _apply_hidden_environments(snapshot: dict[str, Any], sink: Sink, report: ApplyReport) -> None:
    org = sink.client.org
    for project in snapshot.get("projects") or []:
        names = [name for name in project.get("hiddenEnvironments") or [] if name]
        if not names:
            continue
        slug = project.get("slug")
        try:
            sink.put(
                f"/projects/{org}/{slug}/environments/",
                {"environmentNames": names, "isHidden": True},
                f"hidden environments on {slug}",
            )
        except ApiError as exc:
            report.notes.append(
                f"Could not hide environments on {slug} yet ({error_text(exc)}). Re-run after events create them."
            )


def _apply_replay(snapshot: dict[str, Any], sink: Sink, dest: _DestIndex, report: ApplyReport) -> None:
    emails = snapshot.get("replayAccessEmails") or []
    if not emails:
        return
    dest_ids = []
    missing = []
    for email in emails:
        member = dest.members_by_email.get(email)
        user_id = ""
        if member and not member.get("pending"):
            user = member.get("user") if isinstance(member.get("user"), dict) else {}
            user_id = str(user.get("id") or "")
        if user_id:
            dest_ids.append(int(user_id) if user_id.isdigit() else user_id)
        else:
            missing.append(email)
    if missing:
        report.notes.append("Replay access waiting on members: " + ", ".join(missing))
    if not dest_ids and not (snapshot.get("organization") or {}).get("hasGranularReplayPermissions"):
        return
    body = {
        "hasGranularReplayPermissions": True,
        "replayAccessMembers": dest_ids,
    }
    try:
        sink.put(f"/organizations/{sink.client.org}/", body, "replay access")
    except ApiError as exc:
        _fail(report, "replay access", exc)
