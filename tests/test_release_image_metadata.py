"""Release-image metadata contracts for fork maintenance tags."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = (REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
DOCKERFILE = (REPO / "Dockerfile").read_text(encoding="utf-8")


def test_release_image_uses_full_git_tag_as_primary_version_metadata():
    """A tag such as v0.52.41-kumo.5 must survive into tags and OCI labels."""
    full_tag_rule = "type=raw,value=${{ github.ref_name }},priority=1000"
    base_version_rule = r"type=match,pattern=v(\d+\.\d+(?:\.\d+)?),group=1"

    assert full_tag_rule in RELEASE_WORKFLOW
    assert base_version_rule in RELEASE_WORKFLOW
    assert RELEASE_WORKFLOW.index(full_tag_rule) < RELEASE_WORKFLOW.index(base_version_rule)
    assert "labels: ${{ steps.meta.outputs.labels }}" in RELEASE_WORKFLOW
    assert "build-args: HERMES_VERSION=${{ github.ref_name }}" in RELEASE_WORKFLOW


def test_verifier_dependencies_are_baked_into_the_reviewed_image():
    """Verifier-only startup must not depend on broad-WebUI initialization."""
    copy_source = "COPY --chown=root:root . /apptoo"
    install_dependencies = (
        "RUN uv pip install --system --no-cache-dir -r /apptoo/requirements.txt"
    )

    assert copy_source in DOCKERFILE
    assert install_dependencies in DOCKERFILE
    assert DOCKERFILE.index(copy_source) < DOCKERFILE.index(install_dependencies)
