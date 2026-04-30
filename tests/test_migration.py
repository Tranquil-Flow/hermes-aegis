from pathlib import Path

from hermes_aegis import migration


def test_replaced_patch_names_not_in_active_patch_list():
    from hermes_aegis.patches import _PATCHES

    active = {patch.name for patch in _PATCHES}
    assert not (set(migration.REPLACED_PATCHES) & active)


def test_install_plugin_copies_without_caches(tmp_path, monkeypatch):
    source = tmp_path / "src-plugin"
    source.mkdir()
    (source / "plugin.yaml").write_text("name: hermes-aegis\n", encoding="utf-8")
    (source / "__pycache__").mkdir()
    (source / "__pycache__" / "x.pyc").write_bytes(b"cache")

    target = tmp_path / "target-plugin"
    monkeypatch.setattr(migration, "PLUGIN_TARGET", target)

    assert migration.install_plugin(source) is True
    assert (target / "plugin.yaml").exists()
    assert not (target / "__pycache__").exists()


def test_migrate_to_hybrid_reports_legacy_when_hooks_missing(monkeypatch):
    monkeypatch.setattr(migration, "is_v011_or_later", lambda: False)
    assert "legacy patch-only mode" in migration.migrate_to_hybrid()


def test_migrate_to_hybrid_reports_plugin_present(tmp_path, monkeypatch):
    target = tmp_path / "target-plugin"
    target.mkdir()
    monkeypatch.setattr(migration, "PLUGIN_TARGET", target)
    monkeypatch.setattr(migration, "is_v011_or_later", lambda: True)

    result = migration.migrate_to_hybrid(Path("/does/not/matter"))

    assert "Plugin present" in result
    assert "MITM proxy retained" in result


def test_install_plugin_uses_default_source(tmp_path, monkeypatch):
    source = tmp_path / "default-plugin"
    source.mkdir()
    (source / "plugin.yaml").write_text("name: hermes-aegis\n", encoding="utf-8")

    target = tmp_path / "target-plugin"
    monkeypatch.setattr(migration, "DEFAULT_PLUGIN_SOURCE", source)
    monkeypatch.setattr(migration, "PLUGIN_TARGET", target)

    assert migration.install_plugin() is True
    assert (target / "plugin.yaml").exists()


def test_migrate_to_hybrid_warns_when_plugin_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(migration, "is_v011_or_later", lambda: True)
    monkeypatch.setattr(migration, "PLUGIN_TARGET", tmp_path / "missing-target")
    monkeypatch.setattr(migration, "DEFAULT_PLUGIN_SOURCE", tmp_path / "missing-source")

    result = migration.migrate_to_hybrid()

    assert "plugin hook enforcement unavailable" in result
    assert "source patches remain as fallback" not in result
