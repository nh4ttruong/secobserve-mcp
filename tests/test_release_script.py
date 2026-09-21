"""The version rewrites the release script makes, which are the part that silently produces a wrong release."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("release", Path(__file__).parent.parent / "scripts" / "release.py")
assert _spec and _spec.loader
release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release)


def test_the_version_is_rewritten_in_both_places() -> None:
    assert release.bump_pyproject('[project]\nversion = "0.2.2"\nrequires-python = ">=3.11"\n', "0.3.0") == (
        '[project]\nversion = "0.3.0"\nrequires-python = ">=3.11"\n'
    )

    server = '{\n  "version": "0.2.2",\n  "packages": [{"version": "0.2.2"}]\n}'
    assert release.bump_server_json(server, "0.2.2", "0.3.0").count('"version": "0.3.0"') == 2


def test_server_json_must_carry_more_than_the_servers_own_version() -> None:
    """Every package entry carries its own, and a release that bumped only the server would publish a stale one."""
    with pytest.raises(release.Abort, match="found 1"):
        release.bump_server_json('{"version": "0.2.2"}', "0.2.2", "0.3.0")


def test_every_package_version_is_rewritten_however_many_there_are() -> None:
    server = '{"version": "0.2.2", "packages": [{"version": "0.2.2"}, {"version": "0.2.2"}]}'
    assert release.bump_server_json(server, "0.2.2", "0.3.0").count('"version": "0.3.0"') == 3


@pytest.mark.parametrize("version", ("0.3", "v0.3.0", "0.3.0a1", ""))
def test_only_x_y_z_is_accepted(version: str) -> None:
    with pytest.raises(release.Abort, match="not x.y.z"):
        release.parse(version)
