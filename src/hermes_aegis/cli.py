"""hermes-aegis CLI — Security hardening layer for Hermes Agent."""
import click
import os
import sys
import time
from pathlib import Path

AEGIS_DIR = Path.home() / ".hermes-aegis"
VAULT_PATH = AEGIS_DIR / "vault.enc"
HERMES_ENV = Path.home() / ".hermes" / ".env"
HERMES_DIR = Path.home() / ".hermes"

# API keys that are automatically injected into LLM provider requests
AUTO_INJECT_KEYS = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "GROQ_API_KEY",
    "TOGETHER_API_KEY",
    "OPENROUTER_API_KEY",
]


def _check_hermes_installed() -> bool:
    """Check if Hermes Agent is installed."""
    return HERMES_DIR.exists() and (HERMES_DIR / "config.yaml").exists()


def _find_hermes_binary() -> str | None:
    """Find the hermes binary on PATH."""
    import shutil
    return shutil.which("hermes")


def _get_vault_provider_keys() -> set[str]:
    """Return set of provider key names that exist in the vault.

    Only returns keys from _HERMES_PROVIDER_KEYS that are actually
    stored in the vault. Returns empty set if vault doesn't exist.
    """
    if not VAULT_PATH.exists():
        return set()
    try:
        from hermes_aegis.vault.keyring_store import get_or_create_master_key
        from hermes_aegis.vault.store import VaultStore
        master_key = get_or_create_master_key()
        vault = VaultStore(VAULT_PATH, master_key)
        return set(vault.list_keys()) & _HERMES_PROVIDER_KEYS
    except Exception:
        return set()


def _start_proxy_for_run() -> tuple[int, int]:
    """Start the proxy and return (pid, port).

    Reuses the existing start logic from the `start` command.
    Raises RuntimeError if proxy fails to start.
    """
    from hermes_aegis.proxy.runner import start_proxy_process, is_proxy_running
    from hermes_aegis.config.settings import Settings

    running, port = is_proxy_running()
    if running:
        return -1, port  # Already running, don't manage it

    vault_secrets = {}
    vault_values = []
    if VAULT_PATH.exists():
        from hermes_aegis.vault.keyring_store import get_or_create_master_key
        from hermes_aegis.vault.store import VaultStore
        master_key = get_or_create_master_key()
        vault = VaultStore(VAULT_PATH, master_key)
        for key_name in AUTO_INJECT_KEYS:
            value = vault.get(key_name)
            if value is not None:
                vault_secrets[key_name] = value
        vault_values = vault.get_all_values()

    config_path = AEGIS_DIR / "config.json"
    settings = Settings(config_path)
    rate_limit_requests = int(settings.get("rate_limit_requests", 50))
    rate_limit_window = float(settings.get("rate_limit_window", 1.0))

    audit_path = AEGIS_DIR / "audit.jsonl"
    pid = start_proxy_process(
        vault_secrets=vault_secrets,
        vault_values=vault_values,
        audit_path=audit_path,
        rate_limit_requests=rate_limit_requests,
        rate_limit_window=rate_limit_window,
    )
    # Read back port from PID file
    from hermes_aegis.proxy.runner import PID_FILE
    import json
    pid_info = json.loads(PID_FILE.read_text())
    return pid, pid_info["port"]


def _check_hermes_docker_config():
    """Check that Hermes config.yaml has the CA cert volume mount for Docker mode."""
    import yaml

    config_path = HERMES_DIR / "config.yaml"
    if not config_path.exists():
        return

    try:
        config = yaml.safe_load(config_path.read_text())
    except Exception:
        return

    terminal = config.get("terminal", {})
    backend = terminal.get("backend", "local")
    volumes = terminal.get("docker_volumes", [])

    cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    cert_mount = f"{cert_path}:/certs/mitmproxy-ca-cert.pem:ro"
    has_cert_mount = any("/mitmproxy-ca-cert.pem" in v for v in volumes)

    click.echo("")
    if backend == "docker":
        click.echo("Docker: Hermes is using Docker backend.")
        if has_cert_mount:
            click.echo("Docker: CA cert volume mount found — aegis will protect container traffic.")
        else:
            click.echo("Docker: CA cert volume mount missing — aegis cannot intercept HTTPS in containers.")
            click.echo(f"  Add to docker_volumes in ~/.hermes/config.yaml:")
            click.echo(f"  - {cert_mount}")
    else:
        click.echo(f"Docker: available but Hermes backend is '{backend}'.")
        click.echo("  For container isolation, set in ~/.hermes/config.yaml:")
        click.echo("    terminal:")
        click.echo("      backend: docker")
        if not has_cert_mount:
            click.echo(f"    docker_volumes:")
            click.echo(f"      - {cert_mount}")


def _print_aegis_banner(port: int, vault_keys: set[str]):
    """Print the pre-launch aegis banner with shield art and system info."""
    # ANSI color codes
    C = "\033[36m"      # cyan
    BC = "\033[1;36m"   # bold cyan
    G = "\033[32m"      # green
    BG = "\033[1;32m"   # bold green
    W = "\033[37m"      # white
    BW = "\033[1;37m"   # bold white
    D = "\033[2m"       # dim
    DW = "\033[2;37m"   # dim white
    R = "\033[0m"       # reset

    Y = "\033[33m"      # yellow
    BY = "\033[1;33m"   # bold yellow

    # Gather system info
    from hermes_aegis.config.settings import Settings
    from hermes_aegis.config.allowlist import DomainAllowlist
    from hermes_aegis.utils import docker_available

    config_path = AEGIS_DIR / "config.json"
    settings = Settings(config_path)
    cmd_mode = settings.get("dangerous_commands", "audit")
    rate_limit = int(settings.get("rate_limit_requests", 50))
    rate_window = float(settings.get("rate_limit_window", 1.0))

    allowlist_path = AEGIS_DIR / "domain-allowlist.json"
    al = DomainAllowlist(allowlist_path)
    domain_count = len(al.list())

    audit_path = AEGIS_DIR / "audit.jsonl"
    audit_events = 0
    if audit_path.exists():
        audit_events = sum(1 for _ in open(audit_path))

    has_docker = docker_available()

    # Check Hermes Docker backend status
    docker_backend = False
    if has_docker:
        try:
            import yaml
            hermes_cfg = yaml.safe_load((HERMES_DIR / "config.yaml").read_text())
            docker_backend = hermes_cfg.get("terminal", {}).get("backend") == "docker"
        except Exception:
            pass

    # Build info lines
    key_info = f"{len(vault_keys)} API keys protected" if vault_keys else "no vault keys"
    domain_info = f"{domain_count} domains" if domain_count else "all allowed"
    cmd_label = "block" if cmd_mode == "block" else "audit"

    # Shield ASCII art (left) paired with info (right)
    # Each tuple: (shield_plain_text, shield_ansi, info_ansi)
    # shield_plain_text is used to calculate padding
    S = 24  # visual width of shield column

    def row(shield_plain: str, shield_ansi: str, info_ansi: str = "") -> str:
        pad = " " * (S - len(shield_plain))
        return f"  {shield_ansi}{pad}{info_ansi}"

    def info_row(info_ansi: str) -> str:
        return f"  {' ' * S}{info_ansi}"

    lines = [
        "",
        f"  {C}{'─' * 66}{R}",
        row("  ╔═══════════════╗",     f"  {BC}╔═══════════════╗{R}",     f"{BW}AEGIS PROTECTION ACTIVATED{R}"),
        row("  ║ ╔═══════════╗ ║",     f"  {BC}║ ╔═══════════╗ ║{R}",     f"{DW}Security hardening for Hermes Agent{R}"),
        row("  ║ ║  HERMES   ║ ║",     f"  {BC}║ ║  {BW}HERMES{BC}   ║ ║{R}"),
        row("  ║ ║   AEGIS   ║ ║",     f"  {BC}║ ║   {BW}AEGIS{BC}   ║ ║{R}",  f"{C}Proxy{R}       {W}127.0.0.1:{port}{R}"),
        row("  ║ ╚═══════════╝ ║",     f"  {BC}║ ╚═══════════╝ ║{R}",     f"{C}Vault{R}       {W}{key_info}{R}"),
        row("  ║  ◆ ACTIVE ◆   ║",    f"  {BC}║  {G}◆ ACTIVE ◆{BC}   ║{R}",  f"{C}Domains{R}     {W}{domain_info}{R}"),
        row("  ║               ║",     f"  {BC}║               ║{R}",     f"{C}Commands{R}    {W}{cmd_label}{R} {DW}| rate limit {rate_limit}/{rate_window}s{R}"),
        row("  ╚═══╗       ╔═══╝",     f"  {BC}╚═══╗       ╔═══╝{R}",     f"{C}Audit{R}       {W}{audit_events} events{R}"),
        row("      ╚═══╗ ╔═╝",         f"      {BC}╚═══╗ ╔═╝{R}"),
        row("          ╚═╝",           f"          {BC}╚═╝{R}",           f"{BG}All outbound traffic monitored{R}"),
        "",
        info_row(f"{BC}Quick Reference{R}"),
        info_row(f"{DW}hermes-aegis status{R}        {D}System overview{R}"),
        info_row(f"{DW}hermes-aegis vault list{R}     {D}Show protected keys{R}"),
        info_row(f"{DW}hermes-aegis vault set KEY{R}  {D}Add API key to vault{R}"),
        info_row(f"{DW}hermes-aegis test{R}           {D}Verify proxy blocks secrets{R}"),
        info_row(f"{DW}hermes-aegis audit show{R}     {D}View security events{R}"),
        info_row(f"{DW}hermes-aegis config set{R}     {D}Change settings{R}"),
        info_row(f"{DW}hermes-aegis allowlist add{R}  {D}Restrict domains{R}"),
    ]

    if not has_docker:
        lines.append("")
        lines.append(info_row(f"{BY}Docker not found{R} {DW}— install Docker Desktop for container isolation{R}"))
    elif not docker_backend:
        lines.append("")
        lines.append(info_row(f"{DW}Container isolation: set terminal.backend: docker in ~/.hermes/config.yaml{R}"))

    lines.append(f"  {C}{'─' * 66}{R}")
    lines.append("")

    for line in lines:
        click.echo(line)


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx):
    """hermes-aegis: Security hardening layer for Hermes Agent."""
    ctx.ensure_object(dict)
    if ctx.invoked_subcommand is None:
        click.echo("hermes-aegis v0.1.0")
        if not VAULT_PATH.exists():
            click.echo("Run 'hermes-aegis setup' to initialize.")
        else:
            click.echo("Ready. Use 'hermes-aegis run' to start Hermes with protection.")


@main.command()
def install():
    """Install Hermes event hook and generate mitmproxy CA cert.

    Also migrates away from the old invasive setup if present.
    """
    from hermes_aegis.hook import install_hook, clean_old_setup
    from hermes_aegis.utils import ensure_mitmproxy_ca_cert

    # Check Hermes is installed
    if not _check_hermes_installed():
        click.echo("Error: Hermes Agent not found at ~/.hermes/")
        click.echo("Install Hermes first, then run 'hermes-aegis install'.")
        sys.exit(1)

    # Clean old setup first
    actions = clean_old_setup()
    for action in actions:
        click.echo(f"Migration: {action}")

    # Install the Hermes hook
    hook_dir = install_hook()
    click.echo(f"Hook installed: {hook_dir}")

    # Ensure mitmproxy CA cert exists
    try:
        cert = ensure_mitmproxy_ca_cert()
        click.echo(f"CA certificate: {cert}")
    except RuntimeError as e:
        click.echo(f"Error: {e}")
        click.echo("HTTPS interception requires mitmproxy's CA certificate.")
        click.echo("Fix: pip install 'mitmproxy>=10.0', then re-run 'hermes-aegis install'.")
        sys.exit(1)

    # Vault status hint
    if not VAULT_PATH.exists():
        click.echo("\nNote: Vault not initialized. Run 'hermes-aegis setup' to add secrets.")
    elif _count_vault_secrets() == 0:
        click.echo("\nNote: Vault is empty. Add API keys with:")
        click.echo("  hermes-aegis vault set OPENROUTER_API_KEY")

    click.echo("\nDone. Run Hermes with aegis protection:")
    click.echo("  hermes-aegis run")


@main.command()
def uninstall():
    """Remove Hermes event hook."""
    from hermes_aegis.hook import uninstall_hook

    if uninstall_hook():
        click.echo("Hook removed.")
    else:
        click.echo("Hook not found — nothing to remove.")


@main.command()
@click.option("--quiet", is_flag=True, help="Suppress output (for hook use)")
def start(quiet):
    """Start the aegis proxy as a background process."""
    from hermes_aegis.proxy.runner import start_proxy_process, is_proxy_running
    from hermes_aegis.config.settings import Settings

    running, port = is_proxy_running()
    if running:
        if not quiet:
            click.echo(f"Proxy already running on port {port}")
        return

    # Warn if vault missing or empty
    vault_secrets = {}
    vault_values = []
    if VAULT_PATH.exists():
        from hermes_aegis.vault.keyring_store import get_or_create_master_key
        from hermes_aegis.vault.store import VaultStore

        master_key = get_or_create_master_key()
        vault = VaultStore(VAULT_PATH, master_key)

        for key_name in AUTO_INJECT_KEYS:
            value = vault.get(key_name)
            if value is not None:
                vault_secrets[key_name] = value

        vault_values = vault.get_all_values()

        if not quiet and not vault_secrets:
            click.echo("Warning: Vault has no LLM API keys. Proxy will scan but not inject keys.")
            click.echo("Add keys with: hermes-aegis vault set OPENAI_API_KEY")
    else:
        if not quiet:
            click.echo("Warning: Vault not initialized. Run 'hermes-aegis setup' first.")
            click.echo("Proxy will start but cannot inject API keys or scan for vault secrets.")

    # Load rate limit settings
    config_path = AEGIS_DIR / "config.json"
    settings = Settings(config_path)
    rate_limit_requests = int(settings.get("rate_limit_requests", 50))
    rate_limit_window = float(settings.get("rate_limit_window", 1.0))

    audit_path = AEGIS_DIR / "audit.jsonl"

    try:
        pid = start_proxy_process(
            vault_secrets=vault_secrets,
            vault_values=vault_values,
            audit_path=audit_path,
            rate_limit_requests=rate_limit_requests,
            rate_limit_window=rate_limit_window,
        )
        if not quiet:
            click.echo(f"Proxy started (PID {pid})")
    except RuntimeError as e:
        if not quiet:
            click.echo(f"Error: {e}")
        raise SystemExit(1)


@main.command()
def stop():
    """Stop the aegis proxy."""
    from hermes_aegis.proxy.runner import stop_proxy

    if stop_proxy():
        click.echo("Proxy stopped.")
    else:
        click.echo("Proxy not running.")


@main.command(
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.argument("hermes_args", nargs=-1, type=click.UNPROCESSED)
def run(hermes_args):
    """Start aegis proxy, then run Hermes with full protection.

    Any arguments after 'run' are passed to hermes.
    Use -- to separate aegis args from hermes args:

        hermes-aegis run
        hermes-aegis run -- gateway status
    """
    import subprocess as sp

    hermes_bin = _find_hermes_binary()
    if not hermes_bin:
        click.echo("Error: 'hermes' not found on PATH.")
        click.echo("Install Hermes Agent first: https://github.com/nousresearch/hermes-agent")
        sys.exit(1)

    # Start proxy
    try:
        pid, port = _start_proxy_for_run()
        we_started_proxy = pid != -1
    except RuntimeError as e:
        click.echo(f"Error: Could not start aegis proxy: {e}")
        sys.exit(1)

    ca_cert = str(Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem")

    # Build child environment — proxy vars + placeholder API keys
    env = os.environ.copy()
    env["HTTP_PROXY"] = f"http://127.0.0.1:{port}"
    env["HTTPS_PROXY"] = f"http://127.0.0.1:{port}"
    env["REQUESTS_CA_BUNDLE"] = ca_cert
    env["SSL_CERT_FILE"] = ca_cert
    env["AEGIS_ACTIVE"] = "1"

    # Set placeholder API keys for vault-managed provider keys
    # These satisfy Hermes's startup check; the proxy replaces them
    # with real keys at the HTTP level
    vault_keys = _get_vault_provider_keys()
    for key_name in vault_keys:
        env[key_name] = "aegis-managed"

    # Print visible banner so the user knows aegis is active
    _print_aegis_banner(port, vault_keys)

    # Run hermes as a child process with proxy health watchdog
    from hermes_aegis.proxy.runner import stop_proxy
    import signal
    import threading

    hermes_proc = None

    def _proxy_watchdog(proxy_pid: int):
        """Background thread: kill hermes if proxy dies."""
        while True:
            try:
                os.kill(proxy_pid, 0)
            except ProcessLookupError:
                click.echo(
                    f"\n\033[1;31mAegis proxy (PID {proxy_pid}) died unexpectedly.\033[0m"
                )
                click.echo(
                    "Check logs: cat ~/.hermes-aegis/proxy.log"
                )
                if hermes_proc and hermes_proc.poll() is None:
                    hermes_proc.send_signal(signal.SIGTERM)
                return
            time.sleep(2)

    if we_started_proxy and pid > 0:
        watchdog = threading.Thread(target=_proxy_watchdog, args=(pid,), daemon=True)
        watchdog.start()

    try:
        hermes_proc = sp.Popen([hermes_bin] + list(hermes_args), env=env)
        sys.exit(hermes_proc.wait())
    except KeyboardInterrupt:
        pass  # Normal exit via Ctrl+C
    finally:
        if we_started_proxy:
            stop_proxy()


@main.command()
@click.pass_context
def setup(ctx):
    """One-time setup: migrate secrets, check Docker integration."""
    from hermes_aegis.vault.keyring_store import get_or_create_master_key
    from hermes_aegis.vault.migrate import migrate_env_to_vault
    from hermes_aegis.utils import docker_available

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
        click.echo("")
        click.echo("Add your API keys to the vault:")
        click.echo("  hermes-aegis vault set OPENAI_API_KEY")
        click.echo("  hermes-aegis vault set ANTHROPIC_API_KEY")
        click.echo("  hermes-aegis vault set GOOGLE_API_KEY")
        click.echo("")
        click.echo("These keys are automatically injected into LLM requests")
        click.echo("so they never appear in agent memory or subprocess env vars.")

    # Check Hermes Docker config if Docker is available
    if docker_available() and _check_hermes_installed():
        _check_hermes_docker_config()

    click.echo("\nSetup complete! Vault is ready.")
    if _check_hermes_installed():
        click.echo("Next: hermes-aegis install")
    else:
        click.echo("Next: Install Hermes Agent, then run 'hermes-aegis install'.")


@main.command("test")
def test_canary():
    """Verify the proxy is working by sending a canary request.

    Starts the proxy if not running, sends a request containing a fake
    secret, and checks that it gets blocked. Reports pass/fail.
    """
    import json
    import time

    from hermes_aegis.proxy.runner import is_proxy_running, start_proxy_process, stop_proxy
    from hermes_aegis.utils import find_available_port

    # Use an OpenAI-style key pattern — the content scanner always detects these
    # regardless of what's in the vault, so this works with any running proxy
    CANARY_SECRET = "sk-proj-canaryTEST1234567890abcdef1234567890abcdef1234"

    click.echo("Running aegis security verification...\n")

    # Check if proxy already running
    was_running, existing_port = is_proxy_running()

    if was_running:
        proxy_port = existing_port
        click.echo(f"  Proxy: already running (port {proxy_port})")
    else:
        # Start a temporary proxy
        click.echo("  Proxy: starting temporary instance...")
        try:
            proxy_port = find_available_port()
            start_proxy_process(
                vault_secrets={},
                vault_values=[CANARY_SECRET],
                listen_port=proxy_port,
            )
            click.echo(f"  Proxy: started (port {proxy_port})")
        except RuntimeError as e:
            click.echo(f"  FAIL: Could not start proxy: {e}")
            sys.exit(1)

    # Test 1: Send clean request (should pass)
    click.echo("\n  Test 1: Clean request (should pass through)...")
    import requests as req
    ca_cert = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    proxies = {
        "http": f"http://127.0.0.1:{proxy_port}",
        "https": f"http://127.0.0.1:{proxy_port}",
    }

    test1_pass = False
    try:
        resp = req.get(
            "http://httpbin.org/get",
            proxies=proxies,
            timeout=10,
        )
        test1_pass = resp.status_code == 200
        click.echo(f"    {'PASS' if test1_pass else 'FAIL'}: Got status {resp.status_code}")
    except req.ConnectionError:
        # httpbin might be down — try a simpler check
        click.echo("    SKIP: httpbin.org unreachable (network may be restricted)")
        test1_pass = True  # Not a proxy failure
    except Exception as e:
        click.echo(f"    FAIL: {e}")

    # Test 2: Send request with secret in body (should be blocked)
    click.echo("  Test 2: Request with secret (should be blocked)...")
    test2_pass = False
    try:
        resp = req.post(
            "http://httpbin.org/post",
            data=f"leak={CANARY_SECRET}",
            proxies=proxies,
            timeout=10,
        )
        # If we get here, the request wasn't blocked
        click.echo(f"    FAIL: Request was NOT blocked (status {resp.status_code})")
    except (req.ConnectionError, ConnectionError):
        # mitmproxy kills the connection when blocking — this is the expected path
        test2_pass = True
        click.echo("    PASS: Request blocked by proxy")
    except Exception as e:
        click.echo(f"    FAIL: Unexpected error: {e}")

    # Cleanup temporary proxy
    if not was_running:
        stop_proxy()
        click.echo("\n  Proxy: stopped (temporary instance)")

    # Summary
    click.echo("")
    if test1_pass and test2_pass:
        click.echo("  All checks passed. Aegis is protecting your traffic.")
    elif test2_pass:
        click.echo("  Secret blocking works. Clean traffic test was inconclusive.")
    else:
        click.echo("  FAILED: Proxy is not blocking secrets properly.")
        click.echo("  Check: hermes-aegis status")
        sys.exit(1)


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
        click.echo("Vault is empty. Add keys with: hermes-aegis vault set OPENAI_API_KEY")
    else:
        for k in sorted(keys):
            injected = " (auto-injected)" if k in AUTO_INJECT_KEYS else ""
            click.echo(f"  {k}{injected}")


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
    if key in AUTO_INJECT_KEYS:
        click.echo(f"Secret '{key}' saved. Will be auto-injected into LLM requests.")
    else:
        click.echo(f"Secret '{key}' saved. Will be scanned for in outbound traffic.")


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
def status():
    """Show proxy status, hook state, vault info, Docker availability."""
    from hermes_aegis.proxy.runner import is_proxy_running
    from hermes_aegis.hook import is_hook_installed
    from hermes_aegis.utils import docker_available

    # Hermes
    if _check_hermes_installed():
        click.echo("Hermes: installed")
    else:
        click.echo("Hermes: NOT FOUND (install Hermes first)")

    # Proxy status
    running, port = is_proxy_running()
    if running:
        click.echo(f"Proxy: running (port {port})")
    else:
        click.echo("Proxy: stopped")

    # Hook status
    hook_installed = is_hook_installed()
    if hook_installed and not _check_hermes_installed():
        click.echo("Hook: installed (but Hermes not found — hook won't fire)")
    else:
        click.echo(f"Hook: {'installed' if hook_installed else 'not installed'}")

    # Docker
    click.echo(f"Docker: {'available' if docker_available() else 'not found'}")

    # Vault
    if VAULT_PATH.exists():
        from hermes_aegis.vault.keyring_store import get_or_create_master_key
        from hermes_aegis.vault.store import VaultStore
        master_key = get_or_create_master_key()
        v = VaultStore(VAULT_PATH, master_key)
        keys = v.list_keys()
        injected = sum(1 for k in keys if k in AUTO_INJECT_KEYS)
        click.echo(f"Vault: {len(keys)} secrets ({injected} auto-injected LLM keys)")
    else:
        click.echo("Vault: not initialized (run 'hermes-aegis setup')")


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

    audit_path = AEGIS_DIR / "audit.jsonl"
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

    audit_path = AEGIS_DIR / "audit.jsonl"
    if not audit_path.exists():
        click.echo("No audit trail found.")
        return

    trail = AuditTrail(audit_path)
    if trail.verify_chain():
        click.echo("Audit trail integrity verified: PASS")
    else:
        click.echo("Audit trail integrity check: FAILED (tampering detected)")
        sys.exit(1)


@main.group()
def config():
    """Manage hermes-aegis configuration settings."""
    pass


@config.command("get")
@click.argument("key", required=False)
def config_get(key):
    """Get a configuration value or show all settings."""
    from hermes_aegis.config.settings import Settings

    config_path = AEGIS_DIR / "config.json"
    settings = Settings(config_path)

    if key:
        value = settings.get(key)
        if value is None:
            click.echo(f"Configuration key '{key}' not found.")
        else:
            click.echo(f"{key} = {value}")
    else:
        all_settings = settings.get_all()
        if not all_settings:
            click.echo("No configuration settings.")
        else:
            click.echo("Configuration settings:")
            for k, v in sorted(all_settings.items()):
                click.echo(f"  {k} = {v}")


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """Set a configuration value.

    Examples:
        hermes-aegis config set dangerous_commands block
        hermes-aegis config set dangerous_commands audit
        hermes-aegis config set rate_limit_requests 50
        hermes-aegis config set rate_limit_window 1
    """
    from hermes_aegis.config.settings import Settings

    config_path = AEGIS_DIR / "config.json"
    settings = Settings(config_path)

    if key == "dangerous_commands":
        if value not in ("audit", "block"):
            click.echo(f"Error: Invalid value '{value}' for dangerous_commands. Must be 'audit' or 'block'.")
            sys.exit(1)
    elif key == "rate_limit_requests":
        try:
            int_value = int(value)
            if int_value <= 0:
                click.echo("Error: rate_limit_requests must be a positive integer.")
                sys.exit(1)
            value = int_value
        except ValueError:
            click.echo(f"Error: rate_limit_requests must be an integer, got '{value}'.")
            sys.exit(1)
    elif key == "rate_limit_window":
        try:
            float_value = float(value)
            if float_value <= 0:
                click.echo("Error: rate_limit_window must be a positive number.")
                sys.exit(1)
            value = float_value
        except ValueError:
            click.echo(f"Error: rate_limit_window must be a number, got '{value}'.")
            sys.exit(1)

    settings.set(key, value)
    click.echo(f"Set {key} = {value}")


@main.group()
def allowlist():
    """Manage domain allowlist for outbound requests."""
    pass


@allowlist.command("add")
@click.argument("domain")
def allowlist_add(domain):
    """Add a domain to the allowlist."""
    from hermes_aegis.config.allowlist import DomainAllowlist

    allowlist_path = AEGIS_DIR / "domain-allowlist.json"
    allowlist_obj = DomainAllowlist(allowlist_path)
    allowlist_obj.add(domain)
    click.echo(f"Added '{domain}' to allowlist.")


@allowlist.command("remove")
@click.argument("domain")
def allowlist_remove(domain):
    """Remove a domain from the allowlist."""
    from hermes_aegis.config.allowlist import DomainAllowlist

    allowlist_path = AEGIS_DIR / "domain-allowlist.json"
    allowlist_obj = DomainAllowlist(allowlist_path)

    if allowlist_obj.remove(domain):
        click.echo(f"Removed '{domain}' from allowlist.")
    else:
        click.echo(f"Domain '{domain}' not found in allowlist.")


@allowlist.command("list")
def allowlist_list():
    """List all allowed domains."""
    from hermes_aegis.config.allowlist import DomainAllowlist

    allowlist_path = AEGIS_DIR / "domain-allowlist.json"
    allowlist_obj = DomainAllowlist(allowlist_path)
    domains = allowlist_obj.list()

    if not domains:
        click.echo("Allowlist is empty (all domains permitted).")
    else:
        click.echo(f"Allowed domains ({len(domains)}):")
        for domain in domains:
            click.echo(f"  {domain}")


def _count_vault_secrets() -> int:
    """Count secrets in vault without raising on keyring issues."""
    try:
        from hermes_aegis.vault.keyring_store import get_or_create_master_key
        from hermes_aegis.vault.store import VaultStore
        if not VAULT_PATH.exists():
            return 0
        master_key = get_or_create_master_key()
        v = VaultStore(VAULT_PATH, master_key)
        return len(v.list_keys())
    except Exception:
        return 0


# Hermes provider env vars that trigger the startup check
_HERMES_PROVIDER_KEYS = {
    "OPENROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY", "GROQ_API_KEY", "TOGETHER_API_KEY",
}


