"""Run the copy CLI against an in-memory Sentry API."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

import httpx

from org_copy import cli, session
from org_copy.cli import main
from org_copy.client import SentryClient, next_link
from tests.fake_sentry import FakeSentry, MemoryOrg, seed

# Tests never read or write the real per-terminal credentials file.
_no_session = mock.patch("org_copy.session._session", return_value=None)


def setUpModule() -> None:
    _no_session.start()


def tearDownModule() -> None:
    _no_session.stop()


class ClientTests(unittest.TestCase):
    def test_next_link_skips_empty_page(self) -> None:
        header = (
            '<https://us.sentry.io/api/0/organizations/o/projects/?cursor=1>; rel="next"; results="false", '
            '<https://us.sentry.io/api/0/organizations/o/projects/?cursor=0>; rel="previous"; results="true"'
        )
        self.assertIsNone(next_link(header))

    def test_pagination_and_rate_limit(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(429, headers={"Retry-After": "0"}, json={"detail": "slow"})
            if "cursor" not in str(request.url):
                link = '<https://us.sentry.io/api/0/organizations/o/projects/?cursor=1>; rel="next"; results="true"'
                return httpx.Response(200, json=[{"slug": "a"}], headers={"Link": link})
            return httpx.Response(200, json=[{"slug": "b"}])

        with SentryClient("https://us.sentry.io", "token", "o", transport=httpx.MockTransport(handler)) as client:
            rows = client.get_all("/organizations/o/projects/")
        self.assertEqual([row["slug"] for row in rows], ["a", "b"])
        self.assertGreaterEqual(calls["n"], 3)

    def test_rate_limit_retry_keeps_query(self) -> None:
        urls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            urls.append(str(request.url))
            if len(urls) == 1:
                return httpx.Response(429, headers={"Retry-After": "0"}, json={"detail": "slow"})
            return httpx.Response(200, json=[])

        with SentryClient("https://us.sentry.io", "token", "o", transport=httpx.MockTransport(handler)) as client:
            client.get_all("/organizations/o/workflows/", {"project": "-1"})
        self.assertEqual(len(urls), 2)
        self.assertTrue(all(url.endswith("?project=-1") for url in urls))


class CopyTests(unittest.TestCase):
    def test_export_plan_and_apply_round_trip(self) -> None:
        fake = seed()
        transport = httpx.MockTransport(fake.handle)
        original = SentryClient.__init__

        def patched(self, host: str, token: str, org: str, **kwargs: object) -> None:
            kwargs["transport"] = transport
            original(self, host, token, org, **kwargs)

        previous = os.getcwd()
        work = tempfile.TemporaryDirectory()
        os.chdir(work.name)
        SentryClient.__init__ = patched  # type: ignore[method-assign]
        try:
            self.assertEqual(_run(["export"]), 0)
            snapshot = json.loads(Path("snapshot.json").read_text())
            text = Path("snapshot.json").read_text()
            checklist = Path("manual-checklist.md").read_text()
            self.assertNotIn("org-token-secret-value", text)
            self.assertNotIn("hook-secret", text)
            self.assertNotIn("csp-token-value", text)
            self.assertIn("super-secret-splunk-token", text)
            self.assertNotIn("super-secret-splunk-token", checklist)
            self.assertIn("saml2", checklist)
            self.assertIn("CI Upload", checklist)
            self.assertIn("staging", checklist)
            self.assertEqual(stat.S_IMODE(os.stat("snapshot.json").st_mode), 0o600)

            dest = fake.orgs[("de.sentry.io", "sana-de")]
            before = len(dest.calls)
            plan_out = StringIO()
            self.assertEqual(
                _run(
                    ["plan"],
                    stdout=plan_out,
                ),
                0,
            )
            plan_calls = dest.calls[before:]
            self.assertTrue(plan_out.getvalue())
            self.assertFalse([call for call in plan_calls if call[0] in {"POST", "PUT"}])
            self.assertIn("create team backend", plan_out.getvalue())

            self.assertEqual(
                _run(
                    [
                        "apply",
                        "--send-invites",
                        "--hide-environments",
                        "--apply-replay-access",
                    ]
                ),
                0,
            )
            self._assert_destination(fake)
            checklist = Path("manual-checklist.md").read_text()
            self.assertNotIn("super-secret-splunk-token", checklist)
            self.assertIn("slack", checklist.lower())
            self.assertIn("Could not hide environments", checklist)
            dsn_mode = stat.S_IMODE(os.stat("dsn-map.json").st_mode)
            self.assertEqual(dsn_mode, 0o600)

            again = StringIO()
            self.assertEqual(
                _run(["apply"], stdout=again),
                0,
            )
            self.assertIn("skip team backend", again.getvalue())
            self.assertEqual(len(dest.teams), 1)
            self.assertEqual(len(dest.workflows), len(fake.orgs[("us.sentry.io", "sana-us")].workflows))
            self.assertEqual(len(dest.projects), 2)
            self._assert_destination(fake)
        finally:
            SentryClient.__init__ = original  # type: ignore[method-assign]
            os.chdir(previous)
            work.cleanup()

    def _assert_destination(self, fake) -> None:
        dest = fake.orgs[("de.sentry.io", "sana-de")]
        self.assertTrue(dest.fields["require2FA"])
        self.assertEqual(dest.fields["relayPiiConfig"], '{"rules":{}}')
        self.assertNotIn("hideAiFeatures", dest.fields)
        project = dest.projects["api"]
        self.assertEqual(project["fingerprintingRules"], "error.type:DatabaseUnavailable -> database-unavailable")
        self.assertEqual(project["ownership"]["raw"], "path:src/* #backend")
        self.assertFalse(project["ownership"]["codeownersAutoSync"])
        filters = {item["id"]: item["active"] for item in project["filters"]}
        self.assertTrue(filters["browser-extensions"])
        self.assertEqual(filters["legacy-browsers"], ["ie", "safari"])
        keys = {key["name"]: key for key in project["keys"]}
        self.assertEqual(keys["Production"]["rateLimit"], {"window": 60, "count": 10})
        self.assertTrue(keys["Loader"]["dynamicSdkLoaderOptions"]["hasReplay"])
        metric = [detector for detector in project["detectors"] if detector["type"] == "metric_issue"]
        self.assertEqual(len(metric), 1)
        self.assertIsNone(metric[0]["dataSources"][0]["environment"])
        self.assertEqual(metric[0]["dataSources"][0]["queryType"], 0)
        self.assertTrue(metric[0]["owner"].startswith("team:"))
        self._assert_alert_parity(fake)
        workflow = dest.workflows[0]
        actions = workflow["actionFilters"][0]["actions"]
        self.assertTrue(actions)
        self.assertTrue(all(action["type"] == "email" for action in actions))
        team_action = next(action for action in actions if action["config"]["targetType"] == "team")
        self.assertEqual(team_action["config"]["targetIdentifier"], dest.teams["backend"]["id"])
        self.assertEqual(len(project["rules"]), 1)
        self.assertEqual(project["rules"][0]["name"], "After hours")
        self.assertEqual(dest.alert_rules[0]["projects"], ["api"])
        self.assertNotIn("slack", json.dumps(dest.alert_rules[0]["triggers"]).lower())
        self.assertEqual(dest.monitors[0]["slug"], "nightly")
        self.assertEqual(dest.dashboards[0]["title"], "Overview")
        self.assertEqual(dest.dashboards[0]["projects"], [int(project["id"])])
        self.assertEqual(len(dest.dashboards), 1)
        self.assertEqual(dest.queries[0]["projects"], [int(project["id"])])
        self.assertEqual(dest.queries[0]["version"], 2)
        self.assertEqual(len(dest.recent_searches), 1)
        self.assertEqual(dest.recent_searches[0]["query"], "is:unresolved level:error")
        self.assertEqual([view["name"] for view in dest.views], ["Prod errors"])
        self.assertEqual(dest.forwarders[0]["config"]["token"], "super-secret-splunk-token")
        self.assertEqual(dest.forwarders[0]["project_ids"], [int(project["id"])])
        invited = [member for member in dest.members if member["email"] == "other@example.com"]
        self.assertEqual(len(invited), 1)
        self.assertEqual(invited[0]["orgRole"], "manager")
        owner = next(member for member in dest.members if member["email"] == "owner@example.com")
        self.assertIn("backend", owner["teamSlugs"])
        dsn_map = json.loads(Path("dsn-map.json").read_text())
        self.assertEqual({item["key"] for item in dsn_map}, {"Production", "Loader"})
        self.assertTrue(all(item["dsn"].startswith("https://") for item in dsn_map))
        self.assertTrue(all("ingest.sentry.io" not in item["dsn"] or "de.sentry.io" in item["dsn"] for item in dsn_map))


    def _assert_alert_parity(self, fake) -> None:
        source = fake.orgs[("us.sentry.io", "sana-us")]
        dest = fake.orgs[("de.sentry.io", "sana-de")]
        self.assertEqual(len(dest.workflows), len(source.workflows))
        self.assertEqual(len(dest.monitors), len(source.monitors))

        def detector_id(project: str, kind: str) -> str:
            found = [item["id"] for item in dest.projects[project]["detectors"] if item["type"] == kind]
            self.assertEqual(len(found), 1, f"{kind} on {project}")
            return str(found[0])

        uptime = next(item for item in dest.projects["api"]["detectors"] if item["type"] == "uptime_domain_failure")
        self.assertEqual(uptime["dataSources"], [{"url": "https://example.com", "method": "GET", "intervalSeconds": 60, "timeoutMs": 5000}])
        self.assertEqual(uptime["config"], {"mode": 1, "environment": "production", "recoveryThreshold": 1, "downtimeThreshold": 3})
        linked = sorted((item["name"], [str(value) for value in item["detectorIds"]]) for item in dest.workflows)
        expected = sorted(
            [
                ("Notify on new issue", [detector_id("api", "metric_issue")]),
                ("Send a notification for high priority issues", [detector_id("api", "issue_stream")]),
                ("Send a notification for high priority issues", [detector_id("web", "issue_stream")]),
                ("Nightly missed", [detector_id("api", "monitor_check_in_failure")]),
                ("Homepage down", [detector_id("api", "uptime_domain_failure")]),
                ("Any new issue", ["300"]),
                ("Draft alert", []),
            ]
        )
        self.assertEqual(linked, expected)
        slack_only = next(item for item in dest.workflows if item["name"] == "Nightly missed")
        self.assertEqual(slack_only["actionFilters"][0]["actions"], [])


class TeamAdminTests(unittest.TestCase):
    def test_promotes_only_org_members(self) -> None:
        fake = FakeSentry()
        dest = fake.add("de.sentry.io", MemoryOrg("sana-de", "2"))

        def dest_member(member_id: str, email: str, org_role: str, pending: bool = False) -> dict:
            return {
                "id": member_id,
                "email": email,
                "orgRole": org_role,
                "pending": pending,
                "teamSlugs": ["backend"],
                "teamRoles": [{"teamSlug": "backend", "role": None}],
            }

        dest.members = [
            dest_member("1", "member@example.com", "member"),
            dest_member("2", "manager@example.com", "manager"),
            dest_member("3", "contrib@example.com", "member"),
            dest_member("4", "pending@example.com", "member", pending=True),
        ]

        def source_member(email: str, org_role: str, team_role: str) -> dict:
            return {
                "email": email,
                "orgRole": org_role,
                "teamSlugs": ["backend"],
                "teamRoles": [{"teamSlug": "backend", "role": team_role}],
            }

        snapshot = {
            "members": [
                source_member("member@example.com", "member", "admin"),
                source_member("manager@example.com", "manager", "admin"),
                source_member("contrib@example.com", "member", "contributor"),
                source_member("pending@example.com", "member", "admin"),
            ]
        }
        transport = httpx.MockTransport(fake.handle)
        original = SentryClient.__init__

        def patched(self, host: str, token: str, org: str, **kwargs: object) -> None:
            kwargs["transport"] = transport
            original(self, host, token, org, **kwargs)

        previous = os.getcwd()
        work = tempfile.TemporaryDirectory()
        os.chdir(work.name)
        SentryClient.__init__ = patched  # type: ignore[method-assign]
        try:
            Path("snapshot.json").write_text(json.dumps(snapshot))
            code = _run(["update-team-admins"])
            self.assertEqual(code, 1)
            puts = [call for call in dest.calls if call[0] == "PUT"]
            self.assertEqual(puts, [("PUT", "/organizations/sana-de/members/1/teams/backend/")])
            roles = {member["email"]: member["teamRoles"][0]["role"] for member in dest.members}
            self.assertEqual(roles["member@example.com"], "admin")
            self.assertIsNone(roles["manager@example.com"])
            self.assertIsNone(roles["contrib@example.com"])
            self.assertIsNone(roles["pending@example.com"])

            dest.members[3]["pending"] = False
            again = StringIO()
            self.assertEqual(
                _run(["update-team-admins"], stdout=again),
                0,
            )
            self.assertIn("skip team role admin for member@example.com on backend", again.getvalue())
            self.assertIn("updated team role admin for pending@example.com on backend", again.getvalue())
        finally:
            SentryClient.__init__ = original  # type: ignore[method-assign]
            os.chdir(previous)
            work.cleanup()


ANSWERS = {
    "Source org slug: ": "sana-us",
    "Source token: ": "us-token",
    "Destination org slug: ": "sana-de",
    "Destination token: ": "de-token",
}


class GuidedTests(unittest.TestCase):
    def _guided(self, choice: str, invites: str = "n", write: str = "y") -> tuple[int, MemoryOrg, str]:
        fake = seed()
        dest = fake.orgs[("de.sentry.io", "sana-de")]
        transport = httpx.MockTransport(fake.handle)
        original = SentryClient.__init__

        def patched(self, host: str, token: str, org: str, **kwargs: object) -> None:
            kwargs["transport"] = transport
            original(self, host, token, org, **kwargs)

        answers = {
            **ANSWERS,
            "Source host [https://us.sentry.io]: ": "",
            "Destination host [https://de.sentry.io]: ": "",
            "Choose 1 or 2: ": choice,
            "Email invites to the source members now? [y/N]: ": invites,
            "Write the changes above to sana-de? [y/N]: ": write,
        }
        previous = os.getcwd()
        work = tempfile.TemporaryDirectory()
        os.chdir(work.name)
        SentryClient.__init__ = patched  # type: ignore[method-assign]
        err = StringIO()
        try:
            with (
                redirect_stdout(StringIO()),
                redirect_stderr(err),
                mock.patch.dict(os.environ),
                mock.patch("sys.stdin.isatty", return_value=True),
                mock.patch("builtins.input", side_effect=answers.__getitem__),
                mock.patch("getpass.getpass", side_effect=answers.__getitem__),
            ):
                code = main([])
            self.assertTrue(Path("snapshot.json").exists())
            self.assertEqual(Path("dsn-map.json").exists(), choice == "1" and write == "y")
        finally:
            SentryClient.__init__ = original  # type: ignore[method-assign]
            os.chdir(previous)
            work.cleanup()
        return code, dest, err.getvalue()

    def test_plan_writes_nothing(self) -> None:
        code, dest, err = self._guided("2")
        self.assertEqual(code, 0)
        self.assertEqual([call for call in dest.calls if call[0] != "GET"], [])
        self.assertIn("Nothing was written to sana-de", err)

    def test_start_migration_runs_end_to_end(self) -> None:
        code, dest, err = self._guided("1")
        self.assertEqual(code, 0)
        self.assertEqual(sorted(dest.projects), ["api", "web"])
        self.assertFalse([call for call in dest.calls if call[0] == "POST" and call[1].endswith("/members/")])
        self.assertIn("start with Review the destination", err)

    def test_start_migration_can_be_stopped_before_writing(self) -> None:
        code, dest, err = self._guided("1", write="n")
        self.assertEqual(code, 1)
        self.assertEqual([call for call in dest.calls if call[0] != "GET"], [])
        self.assertIn("Stopped. Nothing was written to sana-de", err)


class CredentialTests(unittest.TestCase):
    def test_asks_for_org_and_token_when_none_were_saved(self) -> None:
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("sys.stdin.isatty", return_value=True),
            mock.patch("builtins.input", return_value=" sana-de ") as ask,
            mock.patch("getpass.getpass", return_value="de-token") as ask_secret,
        ):
            self.assertEqual(cli._org_and_token("DEST", "Destination"), ("sana-de", "de-token"))
        ask.assert_called_once_with("Destination org slug: ")
        ask_secret.assert_called_once_with("Destination token: ")

    def test_ignores_and_clears_values_from_earlier_sessions(self) -> None:
        err = StringIO()
        with (
            mock.patch.dict(os.environ, {"SOURCE_ORG": "old-org", "SOURCE_TOKEN": "old-token"}, clear=True),
            mock.patch("sys.stdin.isatty", return_value=True),
            mock.patch("builtins.input", return_value="sana-us"),
            mock.patch("getpass.getpass", return_value="us-token"),
            redirect_stderr(err),
        ):
            self.assertEqual(cli._org_and_token("SOURCE", "Source"), ("sana-us", "us-token"))
            self.assertNotIn("SOURCE_ORG", os.environ)
            self.assertNotIn("SOURCE_TOKEN", os.environ)
        self.assertIn("Ignoring SOURCE_ORG and SOURCE_TOKEN from the environment", err.getvalue())
        self.assertNotIn("old-token", err.getvalue())

    def test_without_terminal_exits(self) -> None:
        with (
            mock.patch.dict(os.environ, {"DEST_ORG": "sana-de", "DEST_TOKEN": "de-token"}, clear=True),
            mock.patch("sys.stdin.isatty", return_value=False),
        ):
            with self.assertRaisesRegex(SystemExit, "DEST_ORG"):
                cli._org_and_token("DEST", "Destination")


class SessionTests(unittest.TestCase):
    def setUp(self) -> None:
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.directory = Path(work.name) / "org-copy"
        for patch in (
            mock.patch("org_copy.session._session", return_value=os.getpid()),
            mock.patch("org_copy.session._terminal", return_value="/dev/ttys001"),
            mock.patch("org_copy.session._directory", return_value=self.directory),
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("sys.stdin.isatty", return_value=True),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def _ask(self, answers: dict[str, str]) -> tuple[str, str]:
        with (
            mock.patch("builtins.input", side_effect=answers.__getitem__),
            mock.patch("getpass.getpass", side_effect=answers.__getitem__),
        ):
            return cli._org_and_token("DEST", "Destination")

    def test_offers_the_org_and_token_from_earlier_in_this_terminal(self) -> None:
        token = "sntrys_0123456789abcdef"
        self.assertEqual(
            self._ask({"Destination org slug: ": "sana-de", "Destination token: ": token}), ("sana-de", token)
        )
        file = self.directory / f"{os.getpid()}.json"
        self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        offer = "Destination org sana-de, token sntr...cdef. Use them again? [Y/n]: "
        self.assertEqual(self._ask({offer: ""}), ("sana-de", token))
        self.assertEqual(
            self._ask({offer: "n", "Destination org slug: ": "other-de", "Destination token: ": "other-token"}),
            ("other-de", "other-token"),
        )
        self.assertEqual(session.remembered("DEST"), ("other-de", "other-token"))

    def test_forgets_terminals_that_were_closed_or_reused(self) -> None:
        self.directory.mkdir(mode=0o700)
        closed = self.directory / "999999999.json"
        closed.write_text(json.dumps({"tty": "/dev/ttys009", "DEST": {"org": "old", "token": "old-token"}}))
        reused = self.directory / f"{os.getpid()}.json"
        reused.write_text(json.dumps({"tty": "/dev/ttys002", "DEST": {"org": "old", "token": "old-token"}}))
        self.assertIsNone(session.remembered("DEST"))
        self.assertFalse(closed.exists())
        self.assertFalse(reused.exists())

    def test_does_not_save_into_a_directory_others_can_read(self) -> None:
        self.directory.mkdir(mode=0o755)
        os.chmod(self.directory, 0o755)
        session.remember("DEST", "sana-de", "de-token")
        self.assertEqual(list(self.directory.iterdir()), [])


def _run(args: list[str], stdout: StringIO | None = None) -> int:
    out = stdout or StringIO()
    err = StringIO()
    with (
        redirect_stdout(out),
        redirect_stderr(err),
        mock.patch.dict(os.environ),
        mock.patch("sys.stdin.isatty", return_value=True),
        mock.patch("builtins.input", side_effect=ANSWERS.__getitem__),
        mock.patch("getpass.getpass", side_effect=ANSWERS.__getitem__),
    ):
        return main(args)


if __name__ == "__main__":
    unittest.main()
