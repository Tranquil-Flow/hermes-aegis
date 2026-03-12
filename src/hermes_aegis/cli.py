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


@main.command()
@click.argument("command", nargs=-1, required=True)
@click.pass_context
def run(ctx, command):
    """Run a command with the security layer active.
    
    Tier 1: Installs middleware chain and content scanner.
    Tier 2: Runs inside hardened container with proxy.
    """
    import subprocess
    import sys
    from hermes_aegis.audit.trail import AuditTrail
    
    tier = ctx.obj["tier"]
    audit_path = ARMOR_DIR / "audit.jsonl"
    
    if not VAULT_PATH.exists():
        click.echo("Error: Vault not initialized. Run 'hermes-aegis setup' first.")
        sys.exit(1)
    
    # Initialize audit trail
    trail = AuditTrail(audit_path)
    
    if tier == 1:
        # Tier 1: Install middleware and content scanner
        # For now, just run the command and track in audit
        click.echo(f"[Tier {tier}] Running with security layer...")
        
        # Start tier1 scanner if available
        try:
            from hermes_aegis.tier1.scanner import install_scanner
            from hermes_aegis.vault.keyring_store import get_or_create_master_key
            from hermes_aegis.vault.store import VaultStore
            
            master_key = get_or_create_master_key()
            vault = VaultStore(VAULT_PATH, master_key)
            install_scanner(vault)
            click.echo("Content scanner active.")
        except ImportError:
            click.echo("Warning: Content scanner not available.")
        except Exception as e:
            click.echo(f"Warning: Could not start content scanner: {e}")
        
        # Execute the command
        try:
            result = subprocess.run(
                list(command),
                capture_output=False,
                text=True,
            )
            exit_code = result.returncode
        except FileNotFoundError:
            click.echo(f"Error: Command not found: {command[0]}")
            exit_code = 127
        except Exception as e:
            click.echo(f"Error running command: {e}")
            exit_code = 1
    
    elif tier == 2:
        # Tier 2: Run in container with proxy
        click.echo(f"[Tier {tier}] Starting container with proxy...")
        click.echo("(Tier 2 full implementation deferred)")
        exit_code = 1
    
    else:
        click.echo(f"Unknown tier: {tier}")
        exit_code = 1
    
    # Print audit summary
    _print_audit_summary(trail)
    
    sys.exit(exit_code)


def _print_audit_summary(trail):
    """Print audit trail summary."""
    entries = trail.read_all()
    
    if not entries:
        click.echo("\nAudit Summary: No entries recorded.")
        return
    
    total = len(entries)
    blocked = sum(1 for e in entries if e.decision in ["DENY", "BLOCKED"])
    redacted = sum(1 for e in entries if "[REDACTED]" in str(e.args_redacted))
    
    click.echo("\n=== Audit Summary ===")
    click.echo(f"Total calls: {total}")
    click.echo(f"Blocked calls: {blocked}")
    click.echo(f"Redacted calls: {redacted}")


@main.group()
def audit():
    """Audit trail viewer and integrity checker."""
    pass


@audit.command("show")
@click.option("--all", "show_all", is_flag=True, help="Show all entries (default: last 20)")
def audit_show(show_all):
    """Show audit trail entries."""
    from hermes_aegis.audit.trail import AuditTrail
    from datetime import datetime
    
    audit_path = ARMOR_DIR / "audit.jsonl"
    if not audit_path.exists():
        click.echo("No audit trail found.")
        return
    
    trail = AuditTrail(audit_path)
    entries = trail.read_all()
    
    if not entries:
        click.echo("Audit trail is empty.")
        return
    
    if not show_all:
        entries = entries[-20:]
    
    click.echo(f"Showing {len(entries)} entries:\n")
    for entry in entries:
        timestamp = datetime.fromtimestamp(entry.timestamp) if isinstance(entry.timestamp, float) else entry.timestamp
        click.echo(f"{timestamp} | {entry.tool_name:20} | {entry.decision:12} | {entry.middleware}")


@audit.command("verify")
def audit_verify():
    """Verify audit trail integrity."""
    from hermes_aegis.audit.trail import AuditTrail
    
    audit_path = ARMOR_DIR / "audit.jsonl"
    if not audit_path.exists():
        click.echo("No audit trail found.")
        return
    
    trail = AuditTrail(audit_path)
    if trail.verify_chain():
        click.echo("✓ Audit trail integrity verified: PASS")
    else:
        click.echo("✗ Audit trail integrity check: FAILED (tampering detected)")
        import sys
        sys.exit(1)
