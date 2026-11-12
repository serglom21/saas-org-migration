"""Pure transforms: id remaps, alert-action filtering, and create payloads."""

from __future__ import annotations

from typing import Any

INTEGRATION_HINTS = (
    "azure",
    "discord",
    "github",
    "gitlab",
    "jira",
    "msteams",
    "opsgenie",
    "pagerduty",
    "pager_duty",
    "sentry_app",
    "slack",
    "twilio",
    "vercel",
    "victorops",
    "webhook",
)

ORG_FIELDS = (
    "alertsMemberWrite",
    "allowJoinRequests",
    "allowSharedIssues",
    "attachmentsRole",
    "dataScrubber",
    "dataScrubberDefaults",
    "debugFilesRole",
    "defaultRole",
    "enhancedPrivacy",
    "eventsMemberAdmin",
    "issueAlertsThreadFlag",
    "metricAlertsThreadFlag",
    "openMembership",
    "relayDsnEndpoint",
    "relayPiiConfig",
    "require2FA",
    "safeFields",
    "scrapeJavaScript",
    "scrubIPAddresses",
    "sensitiveFields",
    "storeCrashReports",
    "trustedRelays",
)

OPTIONAL_ORG_FIELDS = (
    "allowMemberInvite",
    "allowMemberProjectCreation",
    "autoEnableCodeReview",
    "autoOpenPrs",
    "defaultAutofixAutomationTuning",
    "defaultAutomatedRunStoppingPoint",
    "defaultCodeReviewTriggers",
    "defaultCodingAgent",
    "defaultSeerScannerAutomation",
    "enableSeerCoding",
    "hideAiFeatures",
)

PROJECT_FIELDS = (
    "allowedDomains",
    "autofixAutomationTuning",
    "builtinSymbolSources",
    "dataScrubber",
    "dataScrubberDefaults",
    "debugFilesRole",
    "defaultEnvironment",
    "digestsMaxDelay",
    "digestsMinDelay",
    "dynamicSamplingBiases",
    "enableAutoReleaseCreation",
    "fingerprintingRules",
    "groupingConfig",
    "groupingEnhancements",
    "highlightContext",
    "highlightTags",
    "name",
    "relayPiiConfig",
    "resolveAge",
    "safeFields",
    "scmSourceContextEnabled",
    "scrapeJavaScript",
    "scrubIPAddresses",
    "secondaryGroupingConfig",
    "secondaryGroupingExpiry",
    "securityTokenHeader",
    "seerScannerAutomation",
    "sensitiveFields",
    "slug",
    "storeCrashReports",
    "subjectPrefix",
    "subjectTemplate",
    "symbolSources",
    "targetSampleRate",
    "tempestFetchScreenshots",
    "verifySSL",
)

PROJECT_OPTION_KEYS = (
    "filters:blacklisted_ips",
    "filters:error_messages",
    "filters:releases",
    "quotas:spike-protection-disabled",
)


def member_email(member: dict[str, Any]) -> str:
    email = member.get("email") or (member.get("user") or {}).get("email") or ""
    return str(email).strip().lower()


def member_user_id(member: dict[str, Any]) -> str:
    user = member.get("user") or {}
    value = user.get("id") or member.get("userId") or ""
    return str(value) if value else ""


def build_user_map(source_members: list[dict[str, Any]], dest_members: list[dict[str, Any]]) -> dict[str, str]:
    """Map source user ids and emails to destination user ids for accepted members."""
    email_to_dest: dict[str, str] = {}
    for member in dest_members:
        if member.get("pending"):
            continue
        email = member_email(member)
        user_id = member_user_id(member)
        if email and user_id:
            email_to_dest[email] = user_id
    mapped: dict[str, str] = {}
    for member in source_members:
        email = member_email(member)
        if not email or email not in email_to_dest:
            continue
        dest_id = email_to_dest[email]
        mapped[email] = dest_id
        source_id = member_user_id(member)
        if source_id:
            mapped[source_id] = dest_id
    return mapped


def parse_owner(owner: Any) -> tuple[str, str] | None:
    if isinstance(owner, str) and ":" in owner:
        kind, _, ident = owner.partition(":")
        if kind in {"user", "team"} and ident:
            return kind, ident
        return None
    if isinstance(owner, dict):
        kind = str(owner.get("type") or "")
        ident = owner.get("id")
        if kind in {"user", "team"} and ident:
            return kind, str(ident)
    return None


def remap_owner(owner: Any, team_map: dict[str, str], user_map: dict[str, str]) -> str | None:
    parsed = parse_owner(owner)
    if parsed is None:
        return None
    kind, ident = parsed
    if kind == "team":
        dest = team_map.get(str(ident))
        return f"team:{dest}" if dest else None
    dest = user_map.get(str(ident))
    return f"user:{dest}" if dest else None


def remap_project_ids(project_ids: list[Any] | None, project_map: dict[str, str]) -> list[Any]:
    remapped: list[Any] = []
    for project_id in project_ids or []:
        if project_id == -1 or str(project_id) == "-1":
            remapped.append(-1)
            continue
        dest = project_map.get(str(project_id))
        if dest is None:
            continue
        remapped.append(int(dest) if str(dest).isdigit() else dest)
    return remapped


def action_type(action: dict[str, Any]) -> str:
    return str(action.get("type") or action.get("id") or "")


def is_integration_action(action: dict[str, Any]) -> bool:
    if action.get("integrationId") or action.get("integration_id"):
        return True
    lowered = action_type(action).lower()
    return any(hint in lowered for hint in INTEGRATION_HINTS)


def is_keepable_action(action: dict[str, Any]) -> bool:
    if is_integration_action(action):
        return False
    lowered = action_type(action).lower()
    config = action.get("config") if isinstance(action.get("config"), dict) else {}
    target = str(config.get("targetType") or action.get("targetType") or "")
    target = target.lower().replace("_", "")
    if lowered == "email" or "mail" in lowered:
        return True
    return target in {"issueowners", "team", "user", "member"}


def action_label(action: dict[str, Any]) -> str:
    config = action.get("config") if isinstance(action.get("config"), dict) else {}
    target = config.get("targetDisplay") or config.get("targetType") or action.get("targetType") or ""
    label = action_type(action) or "action"
    return f"{label} {target}".strip()


def _map_ident(ident: Any, mapping: dict[str, str]) -> str | None:
    if ident in (None, ""):
        return None
    return mapping.get(str(ident)) or mapping.get(str(ident).lower())


def kept_workflow_action(
    action: dict[str, Any], user_map: dict[str, str], team_map: dict[str, str]
) -> dict[str, Any] | None:
    config = dict(action.get("config") or {})
    target = str(config.get("targetType") or "").lower()
    ident = config.get("targetIdentifier")
    if target in {"user", "member"}:
        dest = _map_ident(ident, user_map)
        if ident not in (None, "") and dest is None:
            return None
        if dest is not None:
            config["targetIdentifier"] = dest
    elif target == "team":
        dest = _map_ident(ident, team_map)
        if ident not in (None, "") and dest is None:
            return None
        if dest is not None:
            config["targetIdentifier"] = dest
    data = action.get("data") if isinstance(action.get("data"), dict) else {}
    return {
        "type": action.get("type") or "email",
        "integrationId": None,
        "data": data,
        "config": config,
    }


def split_actions(
    actions: list[dict[str, Any]],
    *,
    user_map: dict[str, str],
    team_map: dict[str, str],
) -> tuple[list[dict[str, Any]], list[str]]:
    kept: list[dict[str, Any]] = []
    dropped: list[str] = []
    for action in actions:
        if not isinstance(action, dict):
            continue
        if not is_keepable_action(action):
            dropped.append(action_label(action))
            continue
        rewritten = kept_workflow_action(action, user_map, team_map)
        if rewritten is None:
            dropped.append(action_label(action) + " (target is not a member of the destination org yet)")
            continue
        kept.append(rewritten)
    return kept, dropped


def fields_to_drop(error_body: Any, current: dict[str, Any]) -> list[str]:
    if not isinstance(error_body, dict):
        return []
    return [
        key
        for key in list(current)
        if key in error_body and key not in {"detail", "non_field_errors"}
    ]


def org_settings_body(organization: dict[str, Any]) -> dict[str, Any]:
    body: dict[str, Any] = {}
    for field in ORG_FIELDS:
        if field not in organization:
            continue
        if field == "trustedRelays":
            relays = _relays(organization.get("trustedRelays"))
            if relays:
                body[field] = relays
            continue
        body[field] = organization[field]
    return body


def optional_org_body(organization: dict[str, Any]) -> dict[str, Any]:
    return {field: organization[field] for field in OPTIONAL_ORG_FIELDS if field in organization}


def _relays(value: Any) -> list[dict[str, Any]]:
    relays: list[dict[str, Any]] = []
    if not isinstance(value, list):
        return relays
    for item in value:
        if not isinstance(item, dict):
            continue
        public_key = item.get("publicKey") or item.get("public_key")
        if not public_key:
            continue
        relays.append(
            {
                "name": item.get("name") or "",
                "publicKey": public_key,
                "description": item.get("description") or "",
            }
        )
    return relays


def project_settings_body(detail: dict[str, Any]) -> dict[str, Any]:
    body = {field: detail[field] for field in PROJECT_FIELDS if field in detail and detail[field] is not None}
    options = detail.get("options") if isinstance(detail.get("options"), dict) else {}
    for key in PROJECT_OPTION_KEYS:
        value = options.get(key)
        if value not in (None, "", [], {}):
            body[key] = value
    return body


def detector_create_body(detector: dict[str, Any], owner: str | None) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    for source in detector.get("dataSources") or []:
        if not isinstance(source, dict):
            continue
        query_obj = source.get("queryObj") if isinstance(source.get("queryObj"), dict) else {}
        query = query_obj.get("snubaQuery") if isinstance(query_obj.get("snubaQuery"), dict) else query_obj
        item: dict[str, Any] = {}
        for key in (
            "aggregate",
            "dataset",
            "environment",
            "eventTypes",
            "query",
            "queryType",
            "timeWindow",
            "extrapolationMode",
        ):
            if key in query and query[key] is not None:
                item[key] = query[key]
        # A null source environment means all environments. Omit is rejected, and "" is rejected as blank.
        environment = query.get("environment")
        item["environment"] = environment if isinstance(environment, str) and environment else None
        if "queryType" not in item:
            item["queryType"] = 1 if item.get("dataset") == "events_analytics_platform" else 0
        if item:
            sources.append(item)
    group = detector.get("conditionGroup") if isinstance(detector.get("conditionGroup"), dict) else {}
    conditions = []
    for condition in group.get("conditions") or []:
        if not isinstance(condition, dict):
            continue
        conditions.append(
            {
                "type": condition.get("type"),
                "comparison": condition.get("comparison"),
                "conditionResult": condition.get("conditionResult"),
            }
        )
    body: dict[str, Any] = {
        "name": detector.get("name"),
        "type": "metric_issue",
        "description": detector.get("description") or "",
        "enabled": detector.get("enabled", True),
        "config": detector.get("config") or {"detectionType": "static"},
        "dataSources": sources,
        "conditionGroup": {
            "logicType": group.get("logicType") or "any",
            "conditions": conditions,
            "actions": [],
        },
        "workflowIds": [],
    }
    if owner:
        body["owner"] = owner
    return body


UPTIME_SOURCE_KEYS = (
    "url",
    "method",
    "headers",
    "body",
    "intervalSeconds",
    "timeoutMs",
    "traceSampling",
    "responseCaptureEnabled",
    "assertion",
)


def uptime_detector_body(detector: dict[str, Any], owner: str | None) -> dict[str, Any]:
    sources = []
    for source in detector.get("dataSources") or []:
        query = source.get("queryObj") if isinstance(source, dict) else None
        if isinstance(query, dict):
            sources.append({key: query[key] for key in UPTIME_SOURCE_KEYS if query.get(key) is not None})
    config = detector.get("config") if isinstance(detector.get("config"), dict) else {}
    # Only manual mode can be set through the API, so auto-detected monitors become manual.
    body_config: dict[str, Any] = {"mode": 1}
    for camel, snake in (
        ("environment", "environment"),
        ("recoveryThreshold", "recovery_threshold"),
        ("downtimeThreshold", "downtime_threshold"),
    ):
        value = config.get(camel, config.get(snake))
        if value is not None:
            body_config[camel] = value
    body: dict[str, Any] = {
        "name": detector.get("name"),
        "type": "uptime_domain_failure",
        "description": detector.get("description") or "",
        "enabled": detector.get("enabled", True),
        "config": body_config,
        "dataSources": sources[:1],
        "workflowIds": [],
    }
    if owner:
        body["owner"] = owner
    return body


def workflow_create_body(
    workflow: dict[str, Any],
    detector_map: dict[str, str],
    owner: str | None,
    user_map: dict[str, str],
    team_map: dict[str, str],
) -> tuple[dict[str, Any], list[str]]:
    dropped: list[str] = []
    triggers = workflow.get("triggers") if isinstance(workflow.get("triggers"), dict) else {}
    action_filters = []
    for action_filter in workflow.get("actionFilters") or []:
        if not isinstance(action_filter, dict):
            continue
        kept, rejected = split_actions(
            list(action_filter.get("actions") or []),
            user_map=user_map,
            team_map=team_map,
        )
        dropped.extend(rejected)
        action_filters.append(
            {
                "logicType": action_filter.get("logicType") or "any-short",
                "conditions": [
                    {
                        "type": condition.get("type"),
                        "comparison": condition.get("comparison"),
                        "conditionResult": condition.get("conditionResult"),
                    }
                    for condition in (action_filter.get("conditions") or [])
                    if isinstance(condition, dict)
                ],
                "actions": kept,
            }
        )
    detector_ids = []
    for detector_id in workflow.get("detectorIds") or []:
        dest = detector_map.get(str(detector_id))
        if dest is not None:
            detector_ids.append(int(dest) if str(dest).isdigit() else dest)
    body: dict[str, Any] = {
        "name": workflow.get("name"),
        "enabled": workflow.get("enabled", True),
        "environment": workflow.get("environment"),
        "config": workflow.get("config") or {},
        "detectorIds": detector_ids,
        "triggers": {
            "logicType": triggers.get("logicType") or "any-short",
            "conditions": [
                {
                    "type": condition.get("type"),
                    "comparison": condition.get("comparison"),
                    "conditionResult": condition.get("conditionResult"),
                }
                for condition in (triggers.get("conditions") or [])
                if isinstance(condition, dict)
            ],
            "actions": [],
        },
        "actionFilters": action_filters,
    }
    if owner:
        body["owner"] = owner
    return body, dropped


def dashboard_body(dashboard: dict[str, Any], project_map: dict[str, str], team_map: dict[str, str]) -> dict[str, Any]:
    widgets = []
    for widget in dashboard.get("widgets") or []:
        if not isinstance(widget, dict):
            continue
        queries = []
        for query in widget.get("queries") or []:
            if not isinstance(query, dict):
                continue
            queries.append(
                {
                    "name": query.get("name") or "",
                    "fields": query.get("fields") or [],
                    "aggregates": query.get("aggregates") or [],
                    "columns": query.get("columns") or [],
                    "conditions": query.get("conditions") or "",
                    "orderby": query.get("orderby") or "",
                    "fieldAliases": query.get("fieldAliases") or [],
                }
            )
        layout = widget.get("layout") if isinstance(widget.get("layout"), dict) else {}
        widgets.append(
            {
                "title": widget.get("title") or "",
                "displayType": widget.get("displayType"),
                "widgetType": widget.get("widgetType"),
                "interval": widget.get("interval"),
                "limit": widget.get("limit"),
                "layout": {
                    "x": layout.get("x", 0),
                    "y": layout.get("y", 0),
                    "w": layout.get("w", 2),
                    "h": layout.get("h", 2),
                    "minH": layout.get("minH", 2),
                },
                "queries": queries,
            }
        )
    permissions = dashboard.get("permissions") if isinstance(dashboard.get("permissions"), dict) else {}
    teams = []
    for team_id in permissions.get("teamsWithEditAccess") or []:
        dest = team_map.get(str(team_id))
        if dest is not None:
            teams.append(int(dest) if str(dest).isdigit() else dest)
    return {
        "title": dashboard.get("title"),
        "widgets": widgets,
        "projects": remap_project_ids(list(dashboard.get("projects") or []), project_map),
        "environment": dashboard.get("environment") or [],
        "period": dashboard.get("period"),
        "filters": dashboard.get("filters") or {},
        "permissions": {
            "isEditableByEveryone": permissions.get("isEditableByEveryone", True),
            "teamsWithEditAccess": teams,
        },
    }


def saved_query_body(query: dict[str, Any], project_map: dict[str, str]) -> dict[str, Any]:
    body = {
        "name": query.get("name"),
        "projects": remap_project_ids(list(query.get("projects") or []), project_map),
        "query": query.get("query") or "",
        "fields": query.get("fields") or [],
        "orderby": query.get("orderby") or "",
        "environment": query.get("environment") or [],
        "range": query.get("range"),
        "yAxis": query.get("yAxis") or [],
        "queryDataset": query.get("queryDataset"),
        "version": query.get("version") or 2,
    }
    return {key: value for key, value in body.items() if value is not None}


# Top-level fields of an Explore saved query that its create endpoint accepts back.
EXPLORE_QUERY_KEYS = (
    "dataset",
    "query",
    "environment",
    "statsPeriod",
    "start",
    "end",
    "interval",
    "crossEvents",
    "agent",
    "errorsOnly",
)


def explore_query_body(query: dict[str, Any], project_map: dict[str, str]) -> dict[str, Any]:
    body = {key: query[key] for key in EXPLORE_QUERY_KEYS if query.get(key) is not None}
    body["name"] = query.get("name")
    body["projects"] = remap_project_ids(list(query.get("projects") or []), project_map)
    return body


def issue_view_body(view: dict[str, Any], project_map: dict[str, str]) -> dict[str, Any]:
    return {
        "name": view.get("name"),
        "query": view.get("query") or "",
        "projects": remap_project_ids(list(view.get("projects") or []), project_map) or [-1],
        "environments": view.get("environments") or [],
        "timeFilters": view.get("timeFilters") or {"period": "14d"},
        "querySort": view.get("querySort") or "date",
        "starred": bool(view.get("starred")),
    }


def public_key_settings(key: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": key.get("name") or key.get("label") or "Default",
        "isActive": key.get("isActive", True),
        "rateLimit": key.get("rateLimit"),
        "dynamicSdkLoaderOptions": key.get("dynamicSdkLoaderOptions") or {},
    }


def replay_emails(organization: dict[str, Any], members: list[dict[str, Any]]) -> list[str]:
    allowed = {str(user_id) for user_id in organization.get("replayAccessMembers") or []}
    emails: list[str] = []
    for member in members:
        user_id = member_user_id(member)
        email = member_email(member)
        if user_id and user_id in allowed and email:
            emails.append(email)
    return emails
