"""Tests for Hermes self-update integration patches."""

from hermes_aegis.patches import _PATCHES


def test_hermes_update_patch_updates_aegis_before_reapplying_patches():
    """`hermes update` should update both Hermes and hermes-aegis in one command."""
    patch = next(p for p in _PATCHES if p.name == "hermes_update_aegis_repatch")

    assert '["hermes-aegis", "update"]' in patch.after
    assert '["hermes-aegis", "install"]' not in patch.after
    assert "Updating hermes-aegis" in patch.after
