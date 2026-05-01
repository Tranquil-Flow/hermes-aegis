"""Tests for Hermes self-update integration patches."""

from hermes_aegis.patches import _PATCHES


def test_hermes_update_patch_updates_aegis_before_reapplying_patches():
    """`hermes update` should update both Hermes and hermes-aegis in one command."""
    patch = next(p for p in _PATCHES if p.name == "hermes_update_aegis_repatch")

    # SemanticPatch: code is in transform.code
    code = patch.after if hasattr(patch, "after") else patch.transform.code
    assert '["hermes-aegis", "update"]' in code
    assert '["hermes-aegis", "install"]' not in code
    assert "Updating hermes-aegis" in code
