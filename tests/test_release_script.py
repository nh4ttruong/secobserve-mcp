"""The text edits the release script makes, which are the part that silently produces a wrong release."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("release", Path(__file__).parent.parent / "scripts" / "release.py")
assert _spec and _spec.loader
release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release)


def test_the_version_is_rewritten_in_all_three_places() -> None:
    assert release.bump_pyproject('[project]\nversion = "0.2.2"\nrequires-python = ">=3.11"\n', "0.3.0") == (
        '[project]\nversion = "0.3.0"\nrequires-python = ">=3.11"\n'
    )

    server = '{\n  "version": "0.2.2",\n  "packages": [{"version": "0.2.2"}]\n}'
    assert release.bump_server_json(server, "0.2.2", "0.3.0").count('"version": "0.3.0"') == 2

    assert release.bump_agents("- Current version: `0.2.2`.\n", "0.3.0") == "- Current version: `0.3.0`.\n"


def test_server_json_must_carry_the_version_exactly_twice() -> None:
    """Both places ship: one is the registry entry, the other is the PyPI package the registry points at."""
    with pytest.raises(release.Abort, match="found 1"):
        release.bump_server_json('{"version": "0.2.2"}', "0.2.2", "0.3.0")


def test_changelog_stamping_moves_unreleased_and_adds_both_links() -> None:
    before = (
        "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- A thing.\n\n## [0.2.2] — 2026-09-19\n\n### Fixed\n\n"
        "- Another thing.\n\n"
        f"[Unreleased]: {release.REPO_URL}/compare/v0.2.2...HEAD\n"
        f"[0.2.2]: {release.REPO_URL}/compare/v0.2.1...v0.2.2\n"
    )
    after = release.stamp_changelog(before, "0.2.2", "0.3.0", "2026-09-20")

    assert "## [Unreleased]\n\n## [0.3.0] — 2026-09-20\n\n### Added\n\n- A thing." in after
    assert f"[Unreleased]: {release.REPO_URL}/compare/v0.3.0...HEAD" in after
    assert f"[0.3.0]: {release.REPO_URL}/compare/v0.2.2...v0.3.0" in after


def test_an_empty_unreleased_section_is_refused() -> None:
    """Releasing nothing publishes a version that cannot ever be replaced."""
    with pytest.raises(release.Abort, match="nothing to release"):
        release.stamp_changelog(
            f"# Changelog\n\n## [Unreleased]\n\n## [0.2.2] — 2026-09-19\n\n- A thing.\n\n"
            f"[Unreleased]: {release.REPO_URL}/compare/v0.2.2...HEAD\n",
            "0.2.2",
            "0.3.0",
            "2026-09-20",
        )


@pytest.mark.parametrize("version", ("0.3", "v0.3.0", "0.3.0a1", ""))
def test_only_x_y_z_is_accepted(version: str) -> None:
    with pytest.raises(release.Abort, match="not x.y.z"):
        release.parse(version)
