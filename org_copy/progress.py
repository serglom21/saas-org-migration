"""Show which section a run is on, so long reads and writes don't look stuck."""

from __future__ import annotations

import sys
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from typing import TextIO, TypeVar

T = TypeVar("T")


class Progress:
    """Prints a line to stderr when each section starts and when it ends.

    In a terminal, the end line replaces the start line, and loops over many
    items count up on it while they run.
    """

    def __init__(self, title: str, total: int, stream: TextIO | None = None):
        self.stream = stream or sys.stderr
        self.live = self.stream.isatty()
        self.total = total
        self.step = 0
        self.label = ""
        print(title, file=self.stream, flush=True)

    @contextmanager
    def section(self, label: str) -> Iterator[list[str]]:
        """Run one section. Append short results such as "3 created" to the yielded list."""
        self.step += 1
        self.label = f"  [{self.step}/{self.total}] {label}"
        self._line(f"{self.label}...", done=False)
        started = time.monotonic()
        summary: list[str] = []
        try:
            yield summary
        finally:
            detail = ", ".join(summary) or "done"
            self._line(f"{self.label}: {detail} ({time.monotonic() - started:.1f}s)", done=True)

    def items(self, values: Iterable[T]) -> Iterator[T]:
        """Yield each value, showing "n/total" on the current section line in a terminal."""
        values = list(values)
        for count, value in enumerate(values, start=1):
            if self.live:
                self._line(f"{self.label}... {count}/{len(values)}", done=False)
            yield value

    def _line(self, text: str, *, done: bool) -> None:
        if self.live:
            # \033[K clears the rest of the line, so a shorter text doesn't leave old characters.
            self.stream.write(f"\r\033[K{text}" + ("\n" if done else ""))
        else:
            self.stream.write(f"{text}\n")
        self.stream.flush()
