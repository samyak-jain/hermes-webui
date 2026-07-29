"""Release-image metadata contracts for fork maintenance tags."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = (REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")


def test_release_image_uses_full_git_tag_as_primary_version_metadata():
    """A tag such as v0.52.41-kumo.5 must survive into tags and OCI labels."""
    full_tag_rule = "type=raw,value=${{ github.ref_name }},priority=1000"
    base_version_rule = r"type=match,pattern=v(\d+\.\d+(?:\.\d+)?),group=1"

    assert full_tag_rule in RELEASE_WORKFLOW
    assert base_version_rule in RELEASE_WORKFLOW
    assert RELEASE_WORKFLOW.index(full_tag_rule) < RELEASE_WORKFLOW.index(base_version_rule)
    assert "labels: ${{ steps.meta.outputs.labels }}" in RELEASE_WORKFLOW
    assert "build-args: HERMES_VERSION=${{ github.ref_name }}" in RELEASE_WORKFLOW
