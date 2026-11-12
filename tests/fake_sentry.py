"""In-memory Sentry API used to exercise export, plan, and apply."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from org_copy.remap import ORG_FIELDS, PROJECT_FIELDS

ORG_WRITE = set(ORG_FIELDS) | {"hasGranularReplayPermissions", "replayAccessMembers"}
PROJECT_WRITE = set(PROJECT_FIELDS)


def _ok(data: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=data)


def _missing() -> httpx.Response:
    return httpx.Response(404, json={"detail": "not found"})


class MemoryOrg:
    def __init__(self, slug: str, org_id: str, fields: dict[str, Any] | None = None):
        self.slug = slug
        self.id = org_id
        self.fields = dict(fields or {})
        self.teams: dict[str, dict[str, Any]] = {}
        self.projects: dict[str, dict[str, Any]] = {}
        self.members: list[dict[str, Any]] = []
        self.workflows: list[dict[str, Any]] = []
        self.monitors: list[dict[str, Any]] = []
        self.org_detectors: list[dict[str, Any]] = []
        self.dashboards: list[dict[str, Any]] = []
        self.queries: list[dict[str, Any]] = []
        self.invite_requests: list[dict[str, Any]] = []
        self.explore_queries: list[dict[str, Any]] = []
        self.views: list[dict[str, Any]] = []
        self.forwarders: list[dict[str, Any]] = []
        self.integrations: list[dict[str, Any]] = []
        self.tokens: list[dict[str, Any]] = []
        self.mappings: list[dict[str, Any]] = []
        self.apps: list[dict[str, Any]] = []
        self.auth_provider: dict[str, Any] | None = None
        self.calls: list[tuple[str, str]] = []
        self._seq = 200

    def next_id(self) -> str:
        self._seq += 1
        return str(self._seq)

    def organization(self) -> dict[str, Any]:
        return {"id": self.id, "slug": self.slug, "name": self.slug, **self.fields}

    def detectors(self, all_projects: bool) -> list[dict[str, Any]]:
        # Like Sentry, org-level detectors are only listed with project=-1.
        rows: list[dict[str, Any]] = list(self.org_detectors) if all_projects else []
        for project in self.projects.values():
            rows.extend(project["detectors"])
        return rows


class FakeSentry:
    def __init__(self) -> None:
        self.orgs: dict[tuple[str, str], MemoryOrg] = {}

    def add(self, host: str, org: MemoryOrg) -> MemoryOrg:
        self.orgs[(host, org.slug)] = org
        return org

    def handle(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        path = request.url.path
        if path.startswith("/api/0"):
            path = path[len("/api/0") :] or "/"
        body = json.loads(request.content) if request.content else {}
        org_slug = _org_slug(path)
        org = self.orgs.get((host, org_slug)) if org_slug else None
        if org is None:
            return _missing()
        org.calls.append((request.method, path))
        try:
            return self._route(org, request.method, path, body, request.url.params)
        except KeyError:
            return _missing()

    def _route(
        self,
        org: MemoryOrg,
        method: str,
        path: str,
        body: dict[str, Any],
        params: httpx.QueryParams,
    ) -> httpx.Response:
        slug = org.slug
        if path == f"/organizations/{slug}/":
            return self._organization(org, method, body)
        if path == f"/organizations/{slug}/teams/":
            return self._teams(org, method, body)
        if path == f"/organizations/{slug}/invite-requests/":
            return _ok(org.invite_requests)
        if path == f"/organizations/{slug}/members/":
            return self._members(org, method, body)
        if path == f"/organizations/{slug}/projects/":
            return _ok(list(org.projects.values()))
        all_projects = params.get("project") == "-1"
        if path == f"/organizations/{slug}/detectors/":
            return _ok(org.detectors(all_projects))
        if path == f"/organizations/{slug}/workflows/" and method == "GET":
            # Like Sentry, workflows without detectors are only listed with project=-1.
            return _ok([item for item in org.workflows if all_projects or item.get("detectorIds")])
        if path == f"/organizations/{slug}/workflows/":
            return self._collection(org.workflows, method, body)
        if path == f"/organizations/{slug}/monitors/" and method == "POST":
            return self._create_monitor(org, body)
        if path == f"/organizations/{slug}/monitors/":
            return self._collection(org.monitors, method, body)
        if path == f"/organizations/{slug}/dashboards/":
            return self._collection(org.dashboards, method, body, id_field="title")
        if path == f"/organizations/{slug}/discover/saved/":
            return self._collection(org.queries, method, body)
        if path == f"/organizations/{slug}/explore/saved/":
            return self._collection(org.explore_queries, method, body)
        if path == f"/organizations/{slug}/group-search-views/":
            return self._views(org, method, body, params.get("createdBy"))
        if path == f"/organizations/{slug}/forwarding/":
            return self._forwarders(org, method, body)
        if path == f"/organizations/{slug}/integrations/":
            return _ok(org.integrations)
        if path == f"/organizations/{slug}/code-mappings/":
            return _ok(org.mappings)
        if path == f"/organizations/{slug}/sentry-app-installations/":
            return _ok(org.apps)
        if path == f"/organizations/{slug}/org-auth-tokens/":
            return _ok(org.tokens)
        if path == f"/organizations/{slug}/auth-provider/":
            return _ok(org.auth_provider) if org.auth_provider else _missing()

        team_members = re.fullmatch(rf"/teams/{slug}/([^/]+)/members/?", path)
        if team_members and method == "GET":
            return _ok(_team_roster(org, team_members.group(1)))

        member_team = re.fullmatch(rf"/organizations/{slug}/members/([^/]+)/teams/([^/]+)/?", path)
        if member_team and method == "POST":
            return self._add_member_team(org, member_team.group(1), member_team.group(2))
        if member_team and method == "PUT":
            return self._set_team_role(org, member_team.group(1), member_team.group(2), body)

        project_create = re.fullmatch(rf"/teams/{slug}/([^/]+)/projects/?", path)
        if project_create and method == "POST":
            return self._create_project(org, project_create.group(1), body)

        project = re.fullmatch(rf"/projects/{slug}/([^/]+)/?", path)
        if project:
            return self._project(org, project.group(1), method, body)

        filters = re.fullmatch(rf"/projects/{slug}/([^/]+)/filters/?", path)
        if filters and method == "GET":
            return _ok(org.projects[filters.group(1)]["filters"])
        one_filter = re.fullmatch(rf"/projects/{slug}/([^/]+)/filters/([^/]+)/?", path)
        if one_filter and method == "PUT":
            return self._put_filter(org, one_filter.group(1), one_filter.group(2), body)

        ownership = re.fullmatch(rf"/projects/{slug}/([^/]+)/ownership/?", path)
        if ownership:
            return self._ownership(org, ownership.group(1), method, body)
        keys = re.fullmatch(rf"/projects/{slug}/([^/]+)/keys/?", path)
        if keys:
            return self._keys(org, keys.group(1), method, body)
        one_key = re.fullmatch(rf"/projects/{slug}/([^/]+)/keys/([^/]+)/?", path)
        if one_key and method == "PUT":
            return self._put_key(org, one_key.group(1), one_key.group(2), body)
        environments = re.fullmatch(rf"/projects/{slug}/([^/]+)/environments/?", path)
        if environments and method == "GET":
            return _ok(org.projects[environments.group(1)]["environments"])
        if environments and method == "PUT":
            return self._hide_environments(org, environments.group(1), body)
        codeowners = re.fullmatch(rf"/projects/{slug}/([^/]+)/codeowners/?", path)
        if codeowners and method == "GET":
            return _ok(org.projects[codeowners.group(1)]["codeowners"])
        hooks = re.fullmatch(rf"/projects/{slug}/([^/]+)/hooks/?", path)
        if hooks and method == "GET":
            return _ok(org.projects[hooks.group(1)]["hooks"])
        extra_team = re.fullmatch(rf"/projects/{slug}/([^/]+)/teams/([^/]+)/?", path)
        if extra_team and method == "POST":
            return _ok({})

        dashboard = re.fullmatch(rf"/organizations/{slug}/dashboards/([^/]+)/?", path)
        if dashboard and method == "GET":
            found = next((item for item in org.dashboards if str(item["id"]) == dashboard.group(1)), None)
            return _ok(found) if found else _missing()
        detector = re.fullmatch(rf"/organizations/{slug}/projects/([^/]+)/detectors/?", path)
        if detector and method == "POST":
            return self._create_detector(org, detector.group(1), body)
        forwarder = re.fullmatch(rf"/organizations/{slug}/forwarding/([^/]+)/?", path)
        if forwarder and method == "PUT":
            return self._put_forwarder(org, forwarder.group(1), body)
        return _missing()

    def _organization(self, org: MemoryOrg, method: str, body: dict[str, Any]) -> httpx.Response:
        if method == "GET":
            return _ok(org.organization())
        unknown = [key for key in body if key not in ORG_WRITE]
        if unknown:
            return httpx.Response(400, json={key: ["Unknown field."] for key in unknown})
        org.fields.update(body)
        return _ok(org.organization())

    def _teams(self, org: MemoryOrg, method: str, body: dict[str, Any]) -> httpx.Response:
        if method == "GET":
            return _ok(list(org.teams.values()))
        team = {"id": org.next_id(), "slug": body["slug"], "name": body.get("name") or body["slug"]}
        org.teams[team["slug"]] = team
        return _ok(team, 201)

    def _members(self, org: MemoryOrg, method: str, body: dict[str, Any]) -> httpx.Response:
        if method == "GET":
            return _ok(org.members)
        member = {
            "id": org.next_id(),
            "email": body["email"],
            "orgRole": body.get("role") or "member",
            "pending": True,
            "user": None,
            "teamSlugs": body.get("teams") or [],
            "teamRoles": body.get("teamRoles") or [],
        }
        org.members.append(member)
        return _ok(member, 201)

    def _add_member_team(self, org: MemoryOrg, member_id: str, team_slug: str) -> httpx.Response:
        for member in org.members:
            if str(member.get("id")) != member_id:
                continue
            slugs = member.setdefault("teamSlugs", [])
            if team_slug not in slugs:
                slugs.append(team_slug)
            return _ok(member, 201)
        return _missing()

    def _set_team_role(self, org: MemoryOrg, member_id: str, team_slug: str, body: dict[str, Any]) -> httpx.Response:
        for member in org.members:
            if str(member.get("id")) != member_id:
                continue
            if team_slug not in (member.get("teamSlugs") or []):
                return _missing()
            roles = [item for item in member.get("teamRoles") or [] if item.get("teamSlug") != team_slug]
            roles.append({"teamSlug": team_slug, "role": body.get("teamRole")})
            member["teamRoles"] = roles
            return _ok({"teamRole": body.get("teamRole")})
        return _missing()

    def _collection(
        self,
        rows: list[dict[str, Any]],
        method: str,
        body: dict[str, Any],
        id_field: str = "name",
    ) -> httpx.Response:
        if method == "GET":
            return _ok(rows)
        created = {"id": body.get("id") or _next_from(rows), **body}
        if "id" not in body:
            created["id"] = _next_from(rows)
        rows.append(created)
        return _ok(created, 201)

    def _views(
        self, org: MemoryOrg, method: str, body: dict[str, Any], created_by: str | None
    ) -> httpx.Response:
        if method == "GET":
            return _ok([view for view in org.views if created_by is None or view.get("createdBy") == created_by])
        created = {"id": _next_from(org.views), "createdBy": "me", **body}
        org.views.append(created)
        return _ok(created, 201)

    def _forwarders(self, org: MemoryOrg, method: str, body: dict[str, Any]) -> httpx.Response:
        if method == "GET":
            return _ok(org.forwarders)
        created = {"id": _next_from(org.forwarders), **body}
        org.forwarders.append(created)
        return _ok(created, 201)

    def _put_forwarder(self, org: MemoryOrg, forwarder_id: str, body: dict[str, Any]) -> httpx.Response:
        for index, item in enumerate(org.forwarders):
            if str(item.get("id")) == forwarder_id:
                org.forwarders[index] = {**item, **body, "id": item["id"]}
                return _ok(org.forwarders[index])
        return _missing()

    def _create_project(self, org: MemoryOrg, team_slug: str, body: dict[str, Any]) -> httpx.Response:
        team = org.teams[team_slug]
        project_id = org.next_id()
        key_id = org.next_id()
        project = {
            "id": project_id,
            "slug": body["slug"],
            "name": body.get("name") or body["slug"],
            "platform": body.get("platform") or "",
            "team": {"id": team["id"], "slug": team["slug"]},
            "teams": [{"id": team["id"], "slug": team["slug"]}],
            "filters": [],
            "ownership": None,
            "keys": [
                {
                    "id": key_id,
                    "name": "Default",
                    "isActive": True,
                    "rateLimit": None,
                    "dynamicSdkLoaderOptions": {},
                    "dsn": {"public": f"https://{key_id}@o{org.id}.ingest.de.sentry.io/{project_id}"},
                }
            ],
            "environments": [],
            "codeowners": [],
            "hooks": [],
            "detectors": [
                {"id": org.next_id(), "projectId": project_id, "name": "Error", "type": "error"},
                {"id": org.next_id(), "projectId": project_id, "name": "Issue stream", "type": "issue_stream"},
            ],
            "options": {},
        }
        org.projects[project["slug"]] = project
        return _ok(project, 201)

    def _create_monitor(self, org: MemoryOrg, body: dict[str, Any]) -> httpx.Response:
        created = {"id": org.next_id(), **body}
        org.monitors.append(created)
        project = org.projects[body["project"]]
        project["detectors"].append(
            {
                "id": org.next_id(),
                "projectId": project["id"],
                "name": body["name"],
                "type": "monitor_check_in_failure",
                "dataSources": [{"queryObj": {"slug": body["slug"]}}],
            }
        )
        return _ok(created, 201)

    def _project(self, org: MemoryOrg, slug: str, method: str, body: dict[str, Any]) -> httpx.Response:
        project = org.projects[slug]
        if method == "GET":
            return _ok(project)
        unknown = [key for key in body if key not in PROJECT_WRITE]
        if unknown:
            return httpx.Response(400, json={key: ["Unknown field."] for key in unknown})
        project.update(body)
        return _ok(project)

    def _put_filter(self, org: MemoryOrg, slug: str, filter_id: str, body: dict[str, Any]) -> httpx.Response:
        filters = org.projects[slug]["filters"]
        active = body.get("subfilters", body.get("active"))
        for item in filters:
            if item["id"] == filter_id:
                item["active"] = active
                return httpx.Response(204)
        filters.append({"id": filter_id, "active": active})
        return httpx.Response(204)

    def _ownership(self, org: MemoryOrg, slug: str, method: str, body: dict[str, Any]) -> httpx.Response:
        project = org.projects[slug]
        if method == "GET":
            return _ok(project["ownership"]) if project["ownership"] else _missing()
        project["ownership"] = body
        return _ok(body)

    def _keys(self, org: MemoryOrg, slug: str, method: str, body: dict[str, Any]) -> httpx.Response:
        project = org.projects[slug]
        if method == "GET":
            return _ok(project["keys"])
        key_id = org.next_id()
        key = {
            "id": key_id,
            "name": body.get("name") or "Default",
            "isActive": True,
            "rateLimit": None,
            "dynamicSdkLoaderOptions": {},
            "dsn": {"public": f"https://{key_id}@o{org.id}.ingest.de.sentry.io/{project['id']}"},
        }
        project["keys"].append(key)
        return _ok(key, 201)

    def _put_key(self, org: MemoryOrg, slug: str, key_id: str, body: dict[str, Any]) -> httpx.Response:
        for key in org.projects[slug]["keys"]:
            if str(key["id"]) == str(key_id):
                key.update(body)
                return _ok(key)
        return _missing()

    def _hide_environments(self, org: MemoryOrg, slug: str, body: dict[str, Any]) -> httpx.Response:
        known = {item["name"] for item in org.projects[slug]["environments"]}
        missing = [name for name in body.get("environmentNames") or [] if name not in known]
        if missing:
            return httpx.Response(400, json={"environmentNames": ["Environment does not exist."]})
        for item in org.projects[slug]["environments"]:
            if item["name"] in body.get("environmentNames", []):
                item["isHidden"] = body.get("isHidden")
        return _ok(org.projects[slug]["environments"])

    def _create_detector(self, org: MemoryOrg, slug: str, body: dict[str, Any]) -> httpx.Response:
        project = org.projects[slug]
        created = {"id": org.next_id(), "projectId": project["id"], **body}
        project["detectors"].append(created)
        return _ok(created, 201)


def _org_slug(path: str) -> str | None:
    match = re.match(r"^/(?:organizations|projects|teams)/([^/]+)", path)
    return match.group(1) if match else None


def _team_roster(org: MemoryOrg, team_slug: str) -> list[dict[str, Any]]:
    roster = []
    for member in org.members:
        slugs = member.get("teamSlugs") or []
        if team_slug in slugs:
            roster.append({**member, "teamRole": _role_for(member, team_slug)})
    return roster


def _role_for(member: dict[str, Any], team_slug: str) -> str | None:
    for role in member.get("teamRoles") or []:
        if role.get("teamSlug") == team_slug:
            return role.get("role")
    return member.get("teamRole")


def _next_from(rows: list[dict[str, Any]]) -> str:
    return str(1000 + len(rows) + 1)


def seed() -> FakeSentry:
    fake = FakeSentry()
    source = fake.add(
        "us.sentry.io",
        MemoryOrg(
            "sana-us",
            "1",
            {
                "hasAuthProvider": True,
                "require2FA": True,
                "defaultRole": "member",
                "openMembership": False,
                "alertsMemberWrite": True,
                "eventsMemberAdmin": False,
                "attachmentsRole": "member",
                "debugFilesRole": "admin",
                "enhancedPrivacy": True,
                "allowSharedIssues": False,
                "allowJoinRequests": False,
                "dataScrubber": True,
                "dataScrubberDefaults": True,
                "sensitiveFields": ["password"],
                "safeFields": ["id"],
                "scrubIPAddresses": True,
                "relayPiiConfig": '{"rules":{}}',
                "trustedRelays": [
                    {"name": "edge", "publicKey": "relay-public", "description": "edge relay"}
                ],
                "scrapeJavaScript": False,
                "storeCrashReports": 5,
                "issueAlertsThreadFlag": True,
                "metricAlertsThreadFlag": False,
                "hideAiFeatures": True,
                "hasGranularReplayPermissions": True,
                "replayAccessMembers": ["51"],
            },
        ),
    )
    source.auth_provider = {"provider": "saml2"}
    source.teams["backend"] = {"id": "1", "slug": "backend", "name": "Backend"}
    source.members = [
        {
            "id": "m-owner",
            "email": "owner@example.com",
            "name": "Owner",
            "orgRole": "owner",
            "pending": False,
            "user": {"id": "50", "email": "owner@example.com"},
            "teamSlugs": ["backend"],
            "teamRoles": [{"teamSlug": "backend", "role": "admin"}],
        },
        {
            "id": "m-other",
            "email": "other@example.com",
            "name": "Other",
            "orgRole": "manager",
            "pending": False,
            "user": {"id": "51", "email": "other@example.com"},
            "teamSlugs": ["backend"],
            "teamRoles": [{"teamSlug": "backend", "role": "admin"}],
        },
    ]
    source.projects["api"] = {
        "id": "10",
        "slug": "api",
        "name": "API",
        "platform": "python",
        "team": {"id": "1", "slug": "backend"},
        "teams": [{"id": "1", "slug": "backend"}],
        "fingerprintingRules": "error.type:DatabaseUnavailable -> database-unavailable",
        "resolveAge": 24,
        "dataScrubber": True,
        "securityToken": "csp-token-value",
        "options": {"sentry:token": "csp-token-value", "filters:error_messages": "Timeout"},
        "latestRelease": {"version": "backend@abc"},
        "filters": [
            {"id": "browser-extensions", "active": True},
            {"id": "legacy-browsers", "active": ["ie", "safari"]},
        ],
        "ownership": {
            "raw": "path:src/* #backend",
            "fallthrough": False,
            "autoAssignment": "Auto Assign to Issue Owner",
            "codeownersAutoSync": True,
        },
        "keys": [
            {
                "id": "k1",
                "name": "Production",
                "isActive": True,
                "rateLimit": {"window": 60, "count": 10},
                "dynamicSdkLoaderOptions": {},
                "dsn": {"public": "https://old@o1.ingest.sentry.io/10", "secret": "do-not-copy"},
            },
            {
                "id": "k2",
                "name": "Loader",
                "isActive": True,
                "rateLimit": None,
                "dynamicSdkLoaderOptions": {"hasReplay": True},
                "dsn": {"public": "https://loader@o1.ingest.sentry.io/10"},
            },
        ],
        "environments": [
            {"name": "production", "isHidden": False},
            {"name": "staging", "isHidden": True},
        ],
        "codeowners": [{"id": "co1", "raw": "* @backend"}],
        "hooks": [{"url": "https://example.com/hook", "events": ["event.alert"], "secret": "hook-secret"}],
        "detectors": [
            {
                "id": "d1",
                "projectId": "10",
                "name": "Error spike detector",
                "type": "metric_issue",
                "enabled": True,
                "owner": "team:1",
                "config": {"detectionType": "static"},
                "dataSources": [
                    {
                        "queryObj": {
                            "snubaQuery": {
                                "dataset": "events",
                                "query": "is:unresolved",
                                "aggregate": "count()",
                                "timeWindow": 3600,
                                "eventTypes": ["error"],
                            }
                        }
                    }
                ],
                "conditionGroup": {
                    "logicType": "any",
                    "conditions": [{"type": "gt", "comparison": 10, "conditionResult": 75}],
                },
            },
            {
                "id": "d2",
                "projectId": "10",
                "name": "Homepage uptime",
                "type": "uptime_domain_failure",
                "dataSources": [
                    {"queryObj": {"url": "https://example.com", "method": "GET", "intervalSeconds": 60, "timeoutMs": 5000}}
                ],
                "config": {"environment": "production", "recovery_threshold": 1, "downtime_threshold": 3, "mode": 3},
            },
            {"id": "d3", "projectId": "10", "name": "Issue stream", "type": "issue_stream"},
            {
                "id": "d5",
                "projectId": "10",
                "name": "Nightly",
                "type": "monitor_check_in_failure",
                "dataSources": [{"queryObj": {"slug": "nightly"}}],
            },
        ],
    }
    source.workflows.append(
        {
            "id": "w1",
            "name": "Notify on new issue",
            "enabled": True,
            "environment": None,
            "config": {"frequency": 30},
            "detectorIds": ["d1"],
            "owner": "team:1",
            "triggers": {"logicType": "any-short", "conditions": [{"type": "first_seen_event", "comparison": True}]},
            "actionFilters": [
                {
                    "logicType": "any-short",
                    "conditions": [],
                    "actions": [
                        {
                            "type": "email",
                            "integrationId": None,
                            "config": {"targetType": "issue_owners", "targetIdentifier": None},
                        },
                        {
                            "type": "email",
                            "integrationId": None,
                            "config": {"targetType": "team", "targetIdentifier": "1"},
                        },
                        {
                            "type": "email",
                            "integrationId": None,
                            "config": {"targetType": "user", "targetIdentifier": "51"},
                        },
                        {
                            "type": "slack",
                            "integrationId": "9",
                            "config": {"targetType": "specific", "targetDisplay": "#alerts"},
                        },
                    ],
                }
            ],
        }
    )
    source.monitors.append(
        {
            "id": "mon1",
            "name": "Nightly",
            "slug": "nightly",
            "status": "active",
            "project": "api",
            "owner": "team:1",
            "config": {"schedule": "0 0 * * *", "schedule_type": "crontab"},
        }
    )
    source.dashboards.extend(
        [
            {
                "id": "dash1",
                "title": "Overview",
                "projects": [10],
                "environment": [],
                "period": "7d",
                "filters": {},
                "widgets": [
                    {
                        "title": "Errors",
                        "displayType": "table",
                        "widgetType": "error-events",
                        "queries": [{"name": "", "fields": ["count()"], "conditions": ""}],
                        "layout": {"x": 0, "y": 0, "w": 2, "h": 2, "minH": 2},
                    }
                ],
            },
            {"id": "dash2", "title": "Prebuilt", "prebuiltId": "1", "projects": [], "widgets": []},
        ]
    )
    source.queries.append(
        {
            "id": "q1",
            "name": "Slow transactions",
            "projects": [10],
            "query": "transaction:/api",
            "fields": ["transaction", "count()"],
            "queryDataset": "transaction-like",
            "version": 2,
        }
    )
    source.invite_requests.append(
        {"id": "ir1", "email": "pending@example.com", "orgRole": "member", "inviteStatus": "requested_to_join"}
    )
    source.explore_queries.extend(
        [
            {
                "id": "e1",
                "name": "Slow spans",
                "projects": [10],
                "dataset": "spans",
                "query": [{"query": "span.op:db", "fields": ["span.description"], "mode": "samples"}],
                "statsPeriod": "24h",
                "isPrebuilt": False,
                "createdBy": {"id": "1"},
            },
            {"id": "e2", "name": "All Transactions", "projects": [], "dataset": "spans", "query": [{}], "isPrebuilt": True},
        ]
    )
    source.views.extend(
        [
            {
                "id": "v1",
                "name": "Prod errors",
                "query": "is:unresolved",
                "projects": [10],
                "environments": [],
                "timeFilters": {"period": "14d"},
                "createdBy": "me",
            },
            {
                "id": "v2",
                "name": "Someone else",
                "query": "is:unresolved",
                "projects": [-1],
                "environments": [],
                "timeFilters": {"period": "14d"},
                "createdBy": "others",
            },
        ]
    )
    source.forwarders.append(
        {
            "id": "f1",
            "provider": "splunk",
            "isEnabled": True,
            "enrollNewProjects": False,
            "config": {"token": "super-secret-splunk-token", "index": "main", "instance_url": "https://splunk.example", "source": "sentry"},
            "enrolledProjects": [{"id": "10", "slug": "api"}],
        }
    )
    source.integrations.append({"provider": {"slug": "slack", "name": "Slack"}, "name": "Workspace", "status": "active"})
    source.mappings.append({"project": {"slug": "api"}, "repo": {"name": "sana/app"}, "stackRoot": "/", "sourceRoot": "src/"})
    source.apps.append({"app": {"slug": "my-app"}})
    source.tokens.append({"id": "t1", "name": "CI Upload", "scopes": ["project:releases"], "token": "org-token-secret-value"})

    _seed_alert_shapes(source)

    dest = fake.add("de.sentry.io", MemoryOrg("sana-de", "2"))
    dest.org_detectors.append({"id": "300", "projectId": None, "name": "All projects", "type": "issue_stream"})
    dest.members.append(
        {
            "id": "m-dest-owner",
            "email": "owner@example.com",
            "name": "Owner",
            "orgRole": "owner",
            "pending": False,
            "user": {"id": "90", "email": "owner@example.com"},
            "teamSlugs": [],
            "teamRoles": [],
        }
    )
    return fake


def _seed_alert_shapes(source: MemoryOrg) -> None:
    """Alerts the way Sentry stores them: same-named per-project alerts, cron, uptime, all-projects, detached."""
    source.projects["web"] = {
        "id": "11",
        "slug": "web",
        "name": "Web",
        "platform": "javascript",
        "team": {"id": "1", "slug": "backend"},
        "teams": [{"id": "1", "slug": "backend"}],
        "options": {},
        "filters": [],
        "ownership": None,
        "keys": [],
        "environments": [],
        "codeowners": [],
        "hooks": [],
        "detectors": [{"id": "d6", "projectId": "11", "name": "Issue stream", "type": "issue_stream"}],
    }
    source.org_detectors.append({"id": "d0", "projectId": None, "name": "All projects", "type": "issue_stream"})
    slack_only = [
        {
            "logicType": "any-short",
            "conditions": [],
            "actions": [{"type": "slack", "integrationId": "9", "config": {"targetType": "specific"}}],
        }
    ]
    for workflow_id, name, detector_ids in (
        ("w2", "Send a notification for high priority issues", ["d3"]),
        ("w3", "Send a notification for high priority issues", ["d6"]),
        ("w4", "Nightly missed", ["d5"]),
        ("w5", "Homepage down", ["d2"]),
        ("w6", "Any new issue", ["d0"]),
        ("w7", "Draft alert", []),
    ):
        source.workflows.append(
            {
                "id": workflow_id,
                "name": name,
                "enabled": True,
                "config": {"frequency": 30},
                "detectorIds": detector_ids,
                "triggers": {"logicType": "any-short", "conditions": []},
                "actionFilters": slack_only,
            }
        )
