"""Checkpoint after plan: compare what the source has with what apply would do, and say why they differ."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from org_copy.apply import NOT_COPIED_START, OBJECT_KINDS, ApplyReport, ObjectKind, action_outcome

# Names shown for each reason. The plan output above lists every one.
_EXAMPLES = 3


@dataclass
class Row:
    kind: ObjectKind
    source: int
    create: int = 0
    existing: list[str] = field(default_factory=list)
    # Reason -> names of the objects not copied for that reason.
    not_copied: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))

    @property
    def missing(self) -> int:
        """Objects in the source that the plan does not mention, such as one with no name."""
        return self.source - self.create - len(self.existing) - sum(len(names) for names in self.not_copied.values())


def render_checkpoint(snapshot: dict[str, Any], report: ApplyReport, source_org: str, dest_org: str) -> str:
    rows = [row for row in (_row(kind, snapshot, report) for kind in OBJECT_KINDS) if row.source or row.create]
    width = max([len(row.kind.label) for row in rows] + [len("Members")])
    columns = (source_org, "To create", "Already there", "Not copied")
    header = " " * (width + 2) + "  ".join(f"{name:>{max(len(name), 6)}}" for name in columns)
    lines = [f"Check before writing to {dest_org}", "", header]
    for row in rows:
        values = (row.source, row.create, len(row.existing), row.source - row.create - len(row.existing))
        cells = "  ".join(f"{value:>{max(len(name), 6)}}" for name, value in zip(columns, values))
        lines.append(f"  {row.kind.label:<{width}}{cells}")
    members = len(snapshot.get("members") or [])
    lines.append(f"  {'Members':<{width}}{members:>{max(len(source_org), 6)}}  invited only if you answer y next")

    explained = [row for row in rows if row.create != row.source]
    if explained:
        lines.extend(["", "Why the numbers differ:"])
    for row in explained:
        lines.append(f"  {row.kind.label}: {row.source} in {source_org}, {row.create} to create")
        if row.existing:
            lines.append(
                f"    {len(row.existing)} already in {dest_org} ({row.kind.match}){_examples(row.existing)}"
            )
        for reason, names in row.not_copied.items():
            lines.append(f"    {len(names)} {reason}{_examples(names)}")
        if row.missing > 0:
            lines.append(f"    {row.missing} not in the plan, such as an entry with no name")
    return "\n".join(lines) + "\n"


def _row(kind: ObjectKind, snapshot: dict[str, Any], report: ApplyReport) -> Row:
    row = Row(kind, kind.count(snapshot))
    for section in report.sections:
        if section.label != kind.section:
            continue
        for action in section.actions:
            subject = action.partition(" ")[2]
            if not subject.startswith(kind.prefixes):
                continue
            outcome = action_outcome(action)
            subject, _, reason = subject.partition(NOT_COPIED_START)
            name = _name(subject, kind)
            if outcome in ("create", "created"):
                row.create += 1
            elif outcome == "not copied":
                row.not_copied[reason.removesuffix(")")].append(name)
            else:
                row.existing.append(name)
        for item in section.failures:
            step = str(item.get("step") or "")
            if step.startswith(kind.prefixes):
                row.not_copied["failed, listed under Went wrong"].append(f"{_name(step, kind)}: {item.get('detail')}")
    return row


def _name(subject: str, kind: ObjectKind) -> str:
    for prefix in kind.prefixes:
        if subject.startswith(prefix):
            return subject[len(prefix) :] or "(no name)"
    return subject


def _examples(names: list[str]) -> str:
    shown = ", ".join(names[:_EXAMPLES])
    more = len(names) - _EXAMPLES
    return f": {shown}" + (f", and {more} more" if more > 0 else "")
