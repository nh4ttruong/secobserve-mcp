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


def test_the_oci_image_tag_moves_with_the_version() -> None:
    """The registry refuses `registryBaseUrl` on an OCI package, so the tag rides in `identifier` and must move."""
    server = (
        '{"version": "0.8.0", "packages": ['
        '{"registryType": "pypi", "identifier": "secobserve-mcp", "version": "0.8.0"}, '
        '{"registryType": "oci", "identifier": "ghcr.io/o/p:0.8.0", "version": "0.8.0"}]}'
    )
    bumped = release.bump_server_json(server, "0.8.0", "1.0.0")

    assert '"ghcr.io/o/p:1.0.0"' in bumped
    assert "0.8.0" not in bumped


def test_an_oci_package_that_still_carries_a_base_url_is_refused_before_it_is_published() -> None:
    """Measured against the live registry: it rejects the whole publish, after PyPI has already accepted."""
    server = (
        '{"version": "0.8.0", "packages": ['
        '{"registryType": "pypi", "identifier": "secobserve-mcp", "version": "0.8.0"}, '
        '{"registryType": "oci", "registryBaseUrl": "https://ghcr.io", '
        '"identifier": "ghcr.io/o/p:0.8.0", "version": "0.8.0"}]}'
    )
    with pytest.raises(release.Abort, match="registryBaseUrl"):
        release.bump_server_json(server, "0.8.0", "1.0.0")


def test_an_oci_identifier_left_on_an_old_tag_is_refused() -> None:
    """A stale image reference publishes cleanly and points every docker user at the previous release."""
    server = (
        '{"version": "0.8.0", "packages": ['
        '{"registryType": "pypi", "identifier": "secobserve-mcp", "version": "0.8.0"}, '
        '{"registryType": "oci", "identifier": "ghcr.io/o/p:0.7.0", "version": "0.8.0"}]}'
    )
    with pytest.raises(release.Abort, match="does not end in the version"):
        release.bump_server_json(server, "0.8.0", "1.0.0")
