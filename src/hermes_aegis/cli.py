"""hermes-aegis CLI — Security hardening layer for Hermes Agent."""
import click
from pathlib import Path

from hermes_aegis.detect import detect_tier

ARMOR_DIR = Path.home() / ".hermes-aegis"
VAULT_PATH = ARMOR_DIR / "vault.enc"
HERMES_ENV = Path.home() / ".hermes" / ".env"


@click.group(invoke_without_command=True)
@click.option("--tier1", is_flag=True, help="Force Tier 1 (skip Docker)")
@click.pass_context
def main(ctx, tier1):
    """hermes-aegis: Security hardening layer for Hermes Agent."""
    ctx.ensure_object(dict)
    ctx.obj["tier"] = detect_tier(force_tier1=tier1)
    if ctx.invoked_subcommand is None:
        tier = ctx.obj["tier"]
        click.echo(f"hermes-aegis v0.1.0 — Tier {tier}")
        if not VAULT_PATH.exists():
            click.echo("Run 'hermes-aegis setup' to initialize.")
        else:
            click.echo("Ready. Use 'hermes-aegis run' to launch Hermes securely.")


@main.command()
@click.pass_context
def setup(ctx):
    """One-time setup: migrate secrets, build container image."""
    from hermes_aegis.vault.keyring_store import get_or_create_master_key
    from hermes_aegis.vault.migrate import migrate_env_to_vault

    master_key = get_or_create_master_key()
    click.echo("Master key stored in OS keyring.")

    if HERMES_ENV.exists():
        result = migrate_env_to_vault(
            HERMES_ENV, VAULT_PATH, master_key, delete_original=False
        )
        click.echo(f"Migrated {result.migrated_count} secrets to encrypted vault.")
        if click.confirm("Delete original .env file? (best-effort secure delete)"):
            migrate_env_to_vault(
                HERMES_ENV, VAULT_PATH, master_key, delete_original=True
            )
            click.echo("Original .env deleted.")
    else:
        click.echo("No .env found — vault initialized empty.")
        from hermes_aegis.vault.store import VaultStore
        VaultStore(VAULT_PATH, master_key)

    tier = ctx.obj["tier"]
    if tier == 2:
        click.echo("Building hardened Docker container image...")
        import subprocess
        dockerfile = Path(__file__).parent / "container" / "Dockerfile"
        result = subprocess.run(
            ["docker", "build", "-t", "hermes-aegis:latest", "-f", str(dockerfile), "."],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            click.echo("Docker image built successfully.")
        else:
            click.echo(f"Docker build failed: {result.stderr[:200]}")
            click.echo("You can retry with: docker build -t hermes-aegis:latest .")

    # Build integrity manifest (optional — only if integrity module is available)
    try:
        from hermes_aegis.middleware.integrity import IntegrityManifest
        hermes_dir = Path.home() / ".hermes"
        manifest = IntegrityManifest(ARMOR_DIR / "manifest.json")
        watched = [d for d in [hermes_dir] if d.exists()]
        if watched:
            manifest.build(watched)
            click.echo(f"Integrity manifest: {len(manifest.entries)} files tracked.")
    except ImportError:
        click.echo("Integrity checking not yet installed — skipping manifest.")

    click.echo("Setup complete!")


@main.group()
def vault():
    """Manage secrets in the encrypted vault."""
    pass


@vault.command("list")
def vault_list():
    """List secret keys (not values)."""
    from hermes_aegis.vault.keyring_store import get_or_create_master_key
    from hermes_aegis.vault.store import VaultStore

    if not VAULT_PATH.exists():
        click.echo("No vault found. Run 'hermes-aegis setup' first.")
        return
    master_key = get_or_create_master_key()
    v = VaultStore(VAULT_PATH, master_key)
    keys = v.list_keys()
    if not keys:
        click.echo("Vault is empty.")
    else:
        for k in sorted(keys):
            click.echo(f"  {k}")


@vault.command("set")
@click.argument("key")
def vault_set(key):
    """Add or update a secret."""
    from hermes_aegis.vault.keyring_store import get_or_create_master_key
    from hermes_aegis.vault.store import VaultStore

    value = click.prompt(f"Value for {key}", hide_input=True)
    master_key = get_or_create_master_key()
    v = VaultStore(VAULT_PATH, master_key)
    v.set(key, value)
    click.echo(f"Secret '{key}' saved.")


@vault.command("remove")
@click.argument("key")
def vault_remove(key):
    """Remove a secret."""
    from hermes_aegis.vault.keyring_store import get_or_create_master_key
    from hermes_aegis.vault.store import VaultStore

    master_key = get_or_create_master_key()
    v = VaultStore(VAULT_PATH, master_key)
    v.remove(key)
    click.echo(f"Secret '{key}' removed.")


@main.command()
@click.pass_context
def status(ctx):
    """Show current tier, vault status, container health."""
    tier = ctx.obj["tier"]
    click.echo(f"Tier: {tier}")
    click.echo(f"Docker: {'available' if tier == 2 else 'not found'}")
    if VAULT_PATH.exists():
        from hermes_aegis.vault.keyring_store import get_or_create_master_key
        from hermes_aegis.vault.store import VaultStore
        master_key = get_or_create_master_key()
        v = VaultStore(VAULT_PATH, master_key)
        click.echo(f"Vault: {len(v.list_keys())} secrets")
    else:
        click.echo("Vault: not initialized")
