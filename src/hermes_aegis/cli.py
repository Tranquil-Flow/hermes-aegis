"""hermes-aegis CLI — Security hardening layer for Hermes Agent."""
import click

from hermes_aegis.detect import detect_tier


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
        click.echo("Run 'hermes-aegis setup' to initialize.")


@main.command()
@click.pass_context
def status(ctx):
    """Show current tier, vault status, container health."""
    tier = ctx.obj["tier"]
    click.echo(f"Tier: {tier}")
    click.echo(f"Docker: {'available' if tier == 2 else 'not found'}")
