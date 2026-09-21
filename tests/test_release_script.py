"""The version rewrites the release script makes, which are the part that silently produces a wrong release."""

from __future__ import annotations

import importlib.util
import json
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


OCI_SERVER = (
    '{"version": "0.8.0", "packages": ['
    '{"registryType": "pypi", "identifier": "secobserve-mcp", "version": "0.8.0"}, '
    '{"registryType": "oci", "identifier": "ghcr.io/o/p:0.8.0"}]}'
)


def test_the_oci_image_tag_moves_with_the_version() -> None:
    """An OCI package states its version only in `identifier`, so no `version` field would ever move it."""
    bumped = release.bump_server_json(OCI_SERVER, "0.8.0", "1.0.0")

    assert '"ghcr.io/o/p:1.0.0"' in bumped
    assert "0.8.0" not in bumped


@pytest.mark.parametrize(
    "extra",
    ('"registryBaseUrl": "https://ghcr.io"', '"version": "0.8.0"', '"fileSha256": "abc"'),
)
def test_an_oci_package_carrying_a_forbidden_field_is_refused_before_anything_is_published(extra: str) -> None:
    """Measured against the live registry: it rejects the whole publish, after PyPI has already accepted."""
    server = OCI_SERVER.replace('"registryType": "oci", ', '"registryType": "oci", ' + extra + ", ")
    field = extra.split('"')[1]

    with pytest.raises(release.Abort, match=field):
        release.bump_server_json(server, "0.8.0", "1.0.0")


def test_an_oci_identifier_left_on_an_old_tag_is_refused() -> None:
    """A stale image reference publishes cleanly and points every docker user at the previous release."""
    server = OCI_SERVER.replace("ghcr.io/o/p:0.8.0", "ghcr.io/o/p:0.7.0")

    with pytest.raises(release.Abort, match="does not end in the version"):
        release.bump_server_json(server, "0.8.0", "1.0.0")


def test_this_repository_satisfies_every_rule_the_registry_applies_to_an_oci_package() -> None:
    """None of these are in the published JSON schema, and v0.8.0 shipped to PyPI before one of them bit."""
    root = Path(__file__).parent.parent
    manifest = json.loads((root / "server.json").read_text())
    oci = [package for package in manifest["packages"] if package["registryType"] == "oci"]
    assert oci, "the OCI package is what the container install instructions point at"

    for package in oci:
        assert "registryBaseUrl" not in package
        assert "version" not in package
        assert "fileSha256" not in package
        registry, _, tagged = package["identifier"].partition("/")
        assert registry == "ghcr.io", "the registry only accepts an allowlisted host"
        assert tagged.endswith(":" + manifest["version"])

    label = f'LABEL io.modelcontextprotocol.server.name="{manifest["name"]}"'
    assert label in (root / "Dockerfile").read_text()


def test_the_image_is_pushed_before_the_manifest_that_points_at_it() -> None:
    """The registry pulls the image during publish, so the reverse order fails with "does not exist"."""
    workflow = (Path(__file__).parent.parent / ".github/workflows/release.yml").read_text()

    assert workflow.index("Publish the container image") < workflow.index("Publish to the MCP Registry")
    assert workflow.index("Publish to PyPI") < workflow.index("Publish the container image")


def test_the_release_script_refuses_a_dockerfile_without_the_ownership_label(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Without it the registry refuses the publish, minutes after PyPI has taken the version for good."""
    (tmp_path / "server.json").write_text(
        '{"name": "io.github.o/p", "version": "1.0.0", "packages": [{"registryType": "oci", '
        '"identifier": "ghcr.io/o/p:1.0.0"}]}'
    )
    (tmp_path / "Dockerfile").write_text("FROM python:3.13-slim\n")
    monkeypatch.setattr(release, "ROOT", tmp_path)

    with pytest.raises(release.Abort, match="ownership label"):
        release.check_oci_label()

    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.13-slim\nLABEL io.modelcontextprotocol.server.name="io.github.o/p"\n'
    )
    release.check_oci_label()
