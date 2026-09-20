#!/usr/bin/env python3
"""Prepare a release: bump the version everywhere, stamp the changelog, run the checks, commit and tag.

It stops before pushing. A tag only becomes a release once it is pushed, and a published PyPI version can
never be replaced, so the irreversible step stays in your hands.

    uv run python scripts/release.py 0.3.0 [--dry-run]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/nh4ttruong/secobserve-mcp"
CHECKS = (
    ("ruff check .", ("uv", "run", "ruff", "check", ".")),
    ("ruff format --check .", ("uv", "run", "ruff", "format", "--check", ".")),
    ("mypy src", ("uv", "run", "mypy", "src")),
    ("pytest -q", ("uv", "run", "pytest", "-q")),
)


class Abort(Exception):
    pass


def git(*args: str) -> str:
    result = subprocess.run(("git", *args), cwd=ROOT, capture_output=True, text=True, check=False)
    if result.returncode:
        raise Abort(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def current_version() -> str:
    match = re.search(r'^version = "(.+?)"$', (ROOT / "pyproject.toml").read_text(), re.MULTILINE)
    if not match:
        raise Abort("no version in pyproject.toml")
    return match.group(1)


def parse(version: str) -> tuple[int, ...]:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise Abort(f"{version} is not x.y.z")
    return tuple(int(part) for part in version.split("."))


def bump_pyproject(text: str, new: str) -> str:
    text, count = re.subn(r'^version = ".+?"$', f'version = "{new}"', text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise Abort("could not rewrite the version in pyproject.toml")
    return text


def bump_server_json(text: str, old: str, new: str) -> str:
    """server.json carries the version twice: the server's own, and the PyPI package's."""
    field = f'"version": "{old}"'
    count = text.count(field)
    if count != 2:
        raise Abort(f"expected 2 version fields in server.json, found {count}")
    return text.replace(field, f'"version": "{new}"')


def bump_agents(text: str, new: str) -> str:
    text, count = re.subn(r"^- Current version: `.+?`\.$", f"- Current version: `{new}`.", text, flags=re.MULTILINE)
    if count != 1:
        raise Abort("could not rewrite 'Current version' in AGENTS.md")
    return text


def stamp_changelog(text: str, old: str, new: str, today: str) -> str:
    if "## [Unreleased]" not in text:
        raise Abort("CHANGELOG.md has no [Unreleased] section")
    body = text.split("## [Unreleased]", 1)[1].split("\n## [", 1)[0]
    if not body.strip():
        raise Abort("the [Unreleased] section is empty; there is nothing to release")

    text = text.replace("## [Unreleased]", f"## [Unreleased]\n\n## [{new}] — {today}", 1)
    unreleased_link = f"[Unreleased]: {REPO_URL}/compare/v{old}...HEAD"
    if unreleased_link not in text:
        raise Abort("could not find the [Unreleased] compare link at the bottom of CHANGELOG.md")
    return text.replace(
        unreleased_link,
        f"[Unreleased]: {REPO_URL}/compare/v{new}...HEAD\n[{new}]: {REPO_URL}/compare/v{old}...v{new}",
        1,
    )


def check_repo_state(new: str) -> None:
    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    if branch != "main":
        raise Abort(f"on branch {branch}; release from main")
    if git("status", "--porcelain"):
        raise Abort("working tree is not clean")
    git("fetch", "origin", "main")
    if git("rev-parse", "HEAD") != git("rev-parse", "origin/main"):
        raise Abort("main and origin/main differ; pull or push first")
    if git("tag", "--list", f"v{new}"):
        raise Abort(f"tag v{new} already exists locally")
    if git("ls-remote", "--tags", "origin", f"v{new}"):
        raise Abort(f"tag v{new} already exists on origin; a published version can never be replaced")


def run_checks() -> None:
    for label, command in CHECKS:
        print(f"  {label}", flush=True)
        if subprocess.run(command, cwd=ROOT, check=False).returncode:
            raise Abort(f"{label} failed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("version", help="the version to release, as x.y.z")
    parser.add_argument("--dry-run", action="store_true", help="show what would change, write nothing")
    args = parser.parse_args()

    try:
        new = args.version
        old = current_version()
        if parse(new) <= parse(old):
            raise Abort(f"{new} is not after the current {old}")
        check_repo_state(new)

        edits = {
            "pyproject.toml": bump_pyproject((ROOT / "pyproject.toml").read_text(), new),
            "server.json": bump_server_json((ROOT / "server.json").read_text(), old, new),
            "AGENTS.md": bump_agents((ROOT / "AGENTS.md").read_text(), new),
            "CHANGELOG.md": stamp_changelog(
                (ROOT / "CHANGELOG.md").read_text(), old, new, datetime.now(UTC).astimezone().date().isoformat()
            ),
        }

        print(f"{old} -> {new}")
        if args.dry_run:
            print("dry run; nothing written. Files that would change: " + ", ".join(edits))
            return 0

        # Checks run before anything is written, so a failure leaves the tree clean instead of half-bumped.
        print("Running the checks the tag will re-run:")
        run_checks()

        for name, content in edits.items():
            (ROOT / name).write_text(content)
        git("add", *edits)
        git("commit", "-m", f"chore(release): v{new}")
        git("tag", f"v{new}")
    except Abort as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"\nCommitted and tagged v{new}. Nothing has been pushed. Review, then:")
    print(f"  git push origin main && git push origin v{new}")
    print(f"\nTo undo: git tag -d v{new} && git reset --hard HEAD~1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
