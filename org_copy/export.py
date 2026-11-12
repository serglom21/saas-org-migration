"""Read a source organization into a snapshot."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from org_copy.client import ApiError, SentryClient
from org_copy.progress import Progress
from org_copy.redact import error_text, redact
from org_copy.remap import member_email, replay_emails

LIST_PARAMS = {"per_page": "100"}
# Without project=-1 these lists only cover the token user's team projects and skip
# org-level detectors and workflows that are not connected to any monitor.
ALL_PROJECTS = {"project": "-1", **LIST_PARAMS}
# Sections export_snapshot runs. The tests check the last one shows [12/12].
EXPORT_SECTIONS = 12


def export_snapshot(client: SentryClient) -> dict[str, Any]:
    org = client.org
    errors: list[dict[str, Any]] = []
    progress = Progress(f"Reading {org}", EXPORT_SECTIONS)
    with progress.section("Organization settings"):
        organization = client.get_json(f"/organizations/{org}/")
    with progress.section("Members") as summary:
        members = _required_list(client, f"/organizations/{org}/members/", LIST_PARAMS, "members", errors)
        summary.append(f"{len(members)} found")
        # The members list leaves out people whose invite or join request still waits for approval.
        requests, request_error = client.get_optional_list(f"/organizations/{org}/invite-requests/", LIST_PARAMS)
        _note_optional(errors, "invite requests", request_error)
        if requests:
            summary.append(f"{len(requests)} waiting for approval")
    with progress.section("Teams") as summary:
        teams = _required_list(client, f"/organizations/{org}/teams/", {"detailed": "0", **LIST_PARAMS}, "teams", errors)
        _attach_team_memberships(client, org, progress.items(teams), members, errors)
        summary.append(f"{len(teams)} found")
    with progress.section("Projects") as summary:
        project_rows = _required_list(
            client, f"/organizations/{org}/projects/", LIST_PARAMS, "projects", errors
        )
        projects = [_export_project(client, org, row, errors) for row in progress.items(project_rows)]
        projects = [project for project in projects if project is not None]
        summary.append(f"{len(projects)} found")

    with progress.section("Monitors") as summary:
        org_detectors: list[dict[str, Any]] = []
        detectors, detector_error = client.get_optional_list(f"/organizations/{org}/detectors/", ALL_PROJECTS)
        if detector_error is None:
            org_detectors = _attach_detectors(projects, detectors, errors)
        else:
            _note_optional(errors, "detectors", detector_error)
            for project in progress.items(projects):
                listed, error = client.get_optional_list(
                    f"/organizations/{org}/projects/{project['slug']}/detectors/",
                    LIST_PARAMS,
                )
                if error and error.status != 404:
                    _note_optional(errors, f"detectors {project['slug']}", error)
                project["detectors"] = listed
        summary.append(f"{len(org_detectors) + sum(len(p['detectors']) for p in projects)} found")

    with progress.section("Alerts") as summary:
        workflows, workflow_error = client.get_optional_list(f"/organizations/{org}/workflows/", ALL_PROJECTS)
        _note_optional(errors, "workflows", workflow_error)
        summary.append(f"{len(workflows)} found")
    with progress.section("Cron monitors") as summary:
        monitors, monitor_error = client.get_optional_list(f"/organizations/{org}/monitors/", ALL_PROJECTS)
        _note_optional(errors, "monitors", monitor_error)
        summary.append(f"{len(monitors)} found")
    with progress.section("Dashboards") as summary:
        dashboards = _export_dashboards(client, org, errors, progress)
        summary.append(f"{len(dashboards)} found")
    with progress.section("Saved queries") as summary:
        saved_queries, query_error = client.get_optional_list(
            f"/organizations/{org}/discover/saved/", LIST_PARAMS
        )
        _note_optional(errors, "saved queries", query_error)
        # Explore holds span, log, and metric queries, plus Discover transaction queries migrated to spans.
        explore_queries, explore_error = client.get_optional_list(f"/organizations/{org}/explore/saved/", LIST_PARAMS)
        _note_optional(errors, "explore saved queries", explore_error)
        summary.append(f"{len(saved_queries) + len(explore_queries)} found")
    with progress.section("Issue views") as summary:
        my_views, my_error = client.get_optional_list(
            f"/organizations/{org}/group-search-views/",
            {"createdBy": "me", **LIST_PARAMS},
        )
        _note_optional(errors, "issue views", my_error)
        other_views, other_error = client.get_optional_list(
            f"/organizations/{org}/group-search-views/",
            {"createdBy": "others", **LIST_PARAMS},
        )
        _note_optional(errors, "other issue views", other_error)
        summary.append(f"{len(my_views) + len(other_views)} found")
    with progress.section("Data forwarders") as summary:
        forwarders, forward_error = client.get_optional_list(f"/organizations/{org}/forwarding/")
        _note_optional(errors, "forwarders", forward_error)
        summary.append(f"{len(forwarders)} found")
    with progress.section("Integrations, apps, and auth tokens"):
        integrations, integration_error = client.get_optional_list(f"/organizations/{org}/integrations/")
        _note_optional(errors, "integrations", integration_error)
        code_mappings, mapping_error = client.get_optional_list(f"/organizations/{org}/code-mappings/")
        _note_optional(errors, "code mappings", mapping_error)
        installations, app_error = client.get_optional_list(f"/organizations/{org}/sentry-app-installations/")
        _note_optional(errors, "sentry app installations", app_error)
        auth_provider, _auth_error = client.get_optional(f"/organizations/{org}/auth-provider/")
        auth_tokens = _export_auth_tokens(client, org, errors)

    return {
        "source": {
            "host": client.base_url,
            "org": organization.get("slug") or org,
            "orgId": str(organization.get("id") or ""),
        },
        "organization": organization,
        "teams": [_public_team(team) for team in teams],
        "members": [_public_member(member) for member in members],
        "replayAccessEmails": replay_emails(organization, members),
        "projects": projects,
        "orgDetectors": org_detectors,
        "workflows": workflows,
        "monitors": monitors,
        "dashboards": dashboards,
        "savedQueries": saved_queries,
        "exploreQueries": explore_queries,
        "issueViews": {"mine": my_views, "others": other_views},
        "forwarders": forwarders,
        "integrations": [_public_integration(item) for item in integrations],
        "codeMappings": [_public_code_mapping(item) for item in code_mappings],
        "sentryAppInstallations": [_public_installation(item) for item in installations],
        "authTokens": auth_tokens,
        "authProvider": auth_provider if isinstance(auth_provider, dict) else None,
        "inviteRequests": [
            {
                "email": item.get("email"),
                "role": item.get("orgRole") or item.get("role"),
                "inviteStatus": item.get("inviteStatus"),
            }
            for item in requests
            if isinstance(item, dict) and item.get("email")
        ],
        "exportErrors": errors,
    }


def _export_project(
    client: SentryClient, org: str, row: dict[str, Any], errors: list[dict[str, Any]]
) -> dict[str, Any] | None:
    slug = row.get("slug")
    if not slug:
        return None
    detail, error = client.get_optional(f"/projects/{org}/{slug}/")
    if not isinstance(detail, dict):
        _note_optional(errors, f"project {slug}", error)
        return None
    detail = _sanitize_project(detail)
    filters, filter_error = client.get_optional_list(f"/projects/{org}/{slug}/filters/")
    _note_optional(errors, f"filters {slug}", filter_error)
    ownership, ownership_error = client.get_optional(f"/projects/{org}/{slug}/ownership/")
    if ownership_error and ownership_error.status != 404:
        _note_optional(errors, f"ownership {slug}", ownership_error)
    keys, key_error = client.get_optional_list(f"/projects/{org}/{slug}/keys/")
    _note_optional(errors, f"keys {slug}", key_error)
    environments, env_error = client.get_optional_list(
        f"/projects/{org}/{slug}/environments/", {"visibility": "all"}
    )
    _note_optional(errors, f"environments {slug}", env_error)
    codeowners, owner_error = client.get_optional_list(f"/projects/{org}/{slug}/codeowners/")
    if owner_error and owner_error.status != 404:
        _note_optional(errors, f"codeowners {slug}", owner_error)
    hooks, hook_error = client.get_optional_list(f"/projects/{org}/{slug}/hooks/")
    if hook_error and hook_error.status != 404:
        _note_optional(errors, f"hooks {slug}", hook_error)
    teams = detail.get("teams") or row.get("teams") or []
    latest = detail.get("latestRelease") if isinstance(detail.get("latestRelease"), dict) else {}
    return {
        "id": str(detail.get("id") or row.get("id") or ""),
        "slug": slug,
        "name": detail.get("name") or row.get("name") or slug,
        "platform": detail.get("platform") or row.get("platform") or "",
        "teams": [{"id": str(team.get("id")), "slug": team.get("slug")} for team in teams if team.get("slug")],
        "detail": detail,
        "filters": filters,
        "ownership": ownership if isinstance(ownership, dict) else None,
        "keys": [_public_client_key(key) for key in keys],
        "environments": environments,
        "hiddenEnvironments": [
            env.get("name") for env in environments if isinstance(env, dict) and env.get("isHidden") and env.get("name")
        ],
        "codeowners": codeowners,
        "serviceHooks": [_public_hook(hook) for hook in hooks],
        "latestRelease": latest.get("version"),
        "detectors": [],
    }


def _export_dashboards(
    client: SentryClient, org: str, errors: list[dict[str, Any]], progress: Progress
) -> list[Any]:
    summaries, error = client.get_optional_list(f"/organizations/{org}/dashboards/", LIST_PARAMS)
    _note_optional(errors, "dashboards", error)
    detailed: list[Any] = []
    for summary in progress.items(summaries):
        dashboard_id = summary.get("id")
        if not dashboard_id:
            continue
        detail, detail_error = client.get_optional(f"/organizations/{org}/dashboards/{dashboard_id}/")
        if isinstance(detail, dict):
            detailed.append(detail)
        else:
            _note_optional(errors, f"dashboard {dashboard_id}", detail_error)
            detailed.append(summary)
    return detailed


def _export_auth_tokens(client: SentryClient, org: str, errors: list[dict[str, Any]]) -> list[dict[str, str]]:
    for path in (f"/organizations/{org}/org-auth-tokens/", f"/organizations/{org}/auth-tokens/"):
        tokens, error = client.get_optional_list(path)
        if error is None:
            return [_public_token(token) for token in tokens if isinstance(token, dict)]
        if error.status != 404:
            _note_optional(errors, "org auth tokens", error)
            return []
    return []


def _attach_team_memberships(
    client: SentryClient,
    org: str,
    teams: Iterable[dict[str, Any]],
    members: list[dict[str, Any]],
    errors: list[dict[str, Any]],
) -> None:
    by_email = {member_email(member): member for member in members if member_email(member)}
    for team in teams:
        slug = team.get("slug")
        if not slug:
            continue
        roster, error = client.get_optional_list(f"/teams/{org}/{slug}/members/", LIST_PARAMS)
        if error and error.status != 404:
            _note_optional(errors, f"team members {slug}", error)
            continue
        for person in roster:
            email = member_email(person)
            member = by_email.get(email)
            if member is None:
                continue
            slugs = member.setdefault("teamSlugs", [])
            if slug not in slugs:
                slugs.append(slug)
            role = person.get("teamRole") or _default_team_role(member)
            if role:
                roles = member.setdefault("teamRoles", [])
                if not any(item.get("teamSlug") == slug for item in roles if isinstance(item, dict)):
                    roles.append({"teamSlug": slug, "role": role})


def _default_team_role(member: dict[str, Any]) -> str | None:
    org_role = member.get("orgRole") or member.get("role")
    if org_role == "member":
        return "contributor"
    if org_role in ("owner", "manager"):
        return "admin"
    return None


def _attach_detectors(
    projects: list[dict[str, Any]], detectors: list[dict[str, Any]], errors: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Attach detectors to their projects and return the org-level ones, such as the all-projects detector.

    A detector whose project was not read cannot be copied, so it is reported instead.
    """
    by_id = {project["id"]: project for project in projects if project.get("id")}
    org_level = []
    unread: dict[str, list[str]] = {}
    for detector in detectors:
        if not detector.get("projectId"):
            org_level.append(detector)
            continue
        project = by_id.get(str(detector["projectId"]))
        if project is None:
            unread.setdefault(str(detector["projectId"]), []).append(str(detector.get("name") or detector.get("id")))
        else:
            project["detectors"].append(detector)
    for project_id, names in unread.items():
        shown = ", ".join(names[:3]) + (f", and {len(names) - 3} more" if len(names) > 3 else "")
        errors.append(
            {
                "step": f"monitors in project {project_id}",
                "status": 0,
                "detail": f"the project was not read, so these monitors were not copied ({len(names)}): {shown}",
            }
        )
    return org_level


def _required_list(
    client: SentryClient,
    path: str,
    params: dict[str, str],
    label: str,
    errors: list[dict[str, Any]],
) -> list[Any]:
    try:
        return client.get_all(path, params)
    except ApiError as exc:
        errors.append({"step": label, "status": exc.status, "detail": error_text(exc)})
        return []


def _note_optional(errors: list[dict[str, Any]], label: str, error: ApiError | None) -> None:
    if error is None or error.status == 404:
        return
    errors.append({"step": label, "status": error.status, "detail": error_text(error)})


def _sanitize_project(detail: dict[str, Any]) -> dict[str, Any]:
    cleaned = dict(detail)
    cleaned.pop("securityToken", None)
    options = dict(cleaned.get("options") or {})
    options.pop("sentry:token", None)
    cleaned["options"] = options
    organization = cleaned.get("organization")
    if isinstance(organization, dict):
        cleaned["organization"] = {"id": organization.get("id"), "slug": organization.get("slug")}
    return redact(cleaned)


def _public_team(team: dict[str, Any]) -> dict[str, Any]:
    return {"id": str(team.get("id")), "slug": team.get("slug"), "name": team.get("name") or team.get("slug")}


def _team_slugs(member: dict[str, Any]) -> list[str]:
    raw = member.get("teamSlugs") or member.get("teams") or []
    slugs: list[str] = []
    for item in raw:
        if isinstance(item, str):
            slugs.append(item)
        elif isinstance(item, dict) and item.get("slug"):
            slugs.append(item["slug"])
    return slugs


def _public_member(member: dict[str, Any]) -> dict[str, Any]:
    user = member.get("user") if isinstance(member.get("user"), dict) else {}
    return {
        "id": str(member.get("id") or ""),
        "email": member_email(member),
        "name": member.get("name") or user.get("name") or "",
        "orgRole": member.get("orgRole") or member.get("role") or "member",
        "pending": bool(member.get("pending")),
        "user": {"id": str(user.get("id") or ""), "email": member_email(member)},
        "teamSlugs": _team_slugs(member),
        "teamRoles": list(member.get("teamRoles") or []),
    }


def _public_client_key(key: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(key.get("id") or ""),
        "name": key.get("name") or key.get("label") or "Default",
        "isActive": key.get("isActive", True),
        "rateLimit": key.get("rateLimit"),
        "dynamicSdkLoaderOptions": key.get("dynamicSdkLoaderOptions") or {},
        "browserSdkVersion": key.get("browserSdkVersion"),
    }


def _public_hook(hook: dict[str, Any]) -> dict[str, Any]:
    return {"url": hook.get("url"), "events": hook.get("events") or []}


def _public_integration(item: dict[str, Any]) -> dict[str, Any]:
    provider = item.get("provider") if isinstance(item.get("provider"), dict) else {}
    return {
        "name": item.get("name") or provider.get("name") or provider.get("slug") or item.get("provider"),
        "provider": provider.get("slug") or item.get("provider"),
        "status": item.get("status"),
    }


def _public_code_mapping(item: dict[str, Any]) -> dict[str, Any]:
    project = item.get("project") if isinstance(item.get("project"), dict) else {}
    repo = item.get("repo") if isinstance(item.get("repo"), dict) else {}
    return {
        "project": project.get("slug") or item.get("projectSlug"),
        "repo": repo.get("name") or item.get("repoName"),
        "stackRoot": item.get("stackRoot"),
        "sourceRoot": item.get("sourceRoot"),
    }


def _public_installation(item: dict[str, Any]) -> dict[str, Any]:
    app = item.get("app") if isinstance(item.get("app"), dict) else {}
    return {"app": app.get("slug") or app.get("name") or item.get("app")}


def _public_token(token: dict[str, Any]) -> dict[str, str]:
    return {
        "id": str(token.get("id") or ""),
        "name": str(token.get("name") or ""),
        "scopes": token.get("scopes") or [],
    }
