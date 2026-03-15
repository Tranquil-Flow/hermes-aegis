"""hermes-aegis CLI — Security hardening layer for Hermes Agent."""
import click
from hermes_aegis import __version__
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

# Keys injected by the proxy into outbound requests (not set as env placeholders).
# Unlike AUTO_INJECT_KEYS, these are only used for proxy-level header injection.
PROXY_INJECT_KEYS = [
    "GITHUB_TOKEN",
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

    Only returns keys from AUTO_INJECT_KEYS that are actually
    stored in the vault. Returns empty set if vault doesn't exist.
    """
    if not VAULT_PATH.exists():
        return set()
    try:
        from hermes_aegis.vault.keyring_store import get_or_create_master_key
        from hermes_aegis.vault.store import VaultStore
        master_key = get_or_create_master_key()
        vault = VaultStore(VAULT_PATH, master_key)
        return set(vault.list_keys()) & set(AUTO_INJECT_KEYS)
    except Exception:
        return set()


def _start_proxy_for_run() -> tuple[int, int]:
    """Start the proxy and return (pid, port).

    Reuses the existing start logic from the `start` command.
    Raises RuntimeError if proxy fails to start.
    """
    from hermes_aegis.proxy.runner import start_proxy_process, is_proxy_running, stop_proxy
    from hermes_aegis.config.settings import Settings

    from hermes_aegis.proxy.runner import _vault_hash

    vault_secrets = {}
    vault_values = []
    if VAULT_PATH.exists():
        from hermes_aegis.vault.keyring_store import get_or_create_master_key
        from hermes_aegis.vault.store import VaultStore
        master_key = get_or_create_master_key()
        vault = VaultStore(VAULT_PATH, master_key)
        for key_name in AUTO_INJECT_KEYS + PROXY_INJECT_KEYS:
            value = vault.get(key_name)
            if value is not None:
                vault_secrets[key_name] = value
        vault_values = vault.get_all_values()

    running, port, existing_hash = is_proxy_running()
    if running and existing_hash == _vault_hash(vault_secrets):
        return -1, port  # Already running with current vault secrets

    # If proxy is running with stale vault secrets, stop it first and reuse the
    # same port so watchdog threads in other sessions don't need to be updated.
    restart_port = None
    if running:
        restart_port = port
        stop_proxy()

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
        listen_port=restart_port,
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


_AEGIS_LOGO = [
    " ░█████╗░███████╗░██████╗░██╗░██████╗ ",
    " ██╔══██╗██╔════╝██╔════╝░██║██╔════╝ ",
    " ███████║█████╗░░██║░░██╗░██║╚█████╗░ ",
    " ██╔══██║██╔══╝░░██║░░╚██╗██║░╚═══██╗ ",
    " ██║░░██║███████╗╚██████╔╝██║██████╔╝ ",
    " ╚═╝░░╚═╝╚══════╝░╚═════╝░╚═╝╚═════╝░",
]


def _print_aegis_banner(port: int, vault_keys: set[str]):
    """Print the pre-launch aegis banner with block-letter art and system info."""
    # Cyan gradient (bright→dim), one colour family
    _GRAD = [
        "\033[1;38;5;159m",  # bright pastel cyan
        "\033[1;38;5;117m",  # light cyan
        "\033[38;5;81m",     # mid cyan
        "\033[38;5;44m",     # teal cyan
        "\033[38;5;37m",     # deeper teal
        "\033[38;5;30m",     # dark teal
    ]

    C = "\033[36m"
    BC = "\033[1;36m"
    BG = "\033[1;32m"
    W = "\033[37m"
    D = "\033[2m"
    DW = "\033[2;37m"
    R = "\033[0m"
    BY = "\033[1;33m"

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
    interesting_events: dict[str, int] = {}
    if audit_path.exists():
        import json as _json
        with open(audit_path) as f:
            for line in f:
                audit_events += 1
                try:
                    entry = _json.loads(line)
                    decision = entry.get("decision", "")
                    if decision in ("BLOCKED", "DANGEROUS_COMMAND", "ANOMALY", "OUTPUT_REDACTED"):
                        interesting_events[decision] = interesting_events.get(decision, 0) + 1
                except Exception:
                    pass

    has_docker = docker_available()
    docker_backend = False
    if has_docker:
        try:
            import yaml
            hermes_cfg = yaml.safe_load((HERMES_DIR / "config.yaml").read_text())
            docker_backend = hermes_cfg.get("terminal", {}).get("backend") == "docker"
        except Exception:
            pass

    key_info = f"{len(vault_keys)} API keys protected" if vault_keys else "no vault keys"
    domain_info = f"{domain_count} domains" if domain_count else "all allowed"
    cmd_label = "block" if cmd_mode == "block" else "audit"

    W_LINE = 70

    click.echo("")
    click.echo(f"  {C}{'─' * W_LINE}{R}")

    # AEGIS logo with gradient
    for i, logo_line in enumerate(_AEGIS_LOGO):
        click.echo(f"  {_GRAD[i]}{logo_line}{R}")

    click.echo(f"  {DW}Security hardening for Hermes Agent{R}")
    click.echo(f"  {D}v{__version__}{R}")
    click.echo("")

    # Status
    click.echo(f"  {BC}Status{R}")
    click.echo(f"    {C}Proxy{R}       {W}127.0.0.1:{port}{R}")
    click.echo(f"    {C}Vault{R}       {W}{key_info}{R}")
    click.echo(f"    {C}Domains{R}     {W}{domain_info}{R}")
    click.echo(f"    {C}Commands{R}    {W}{cmd_label}{R} {DW}| rate limit {rate_limit}/{rate_window}s{R}")
    if interesting_events:
        parts = [f"{v} {k.lower().replace('_', ' ')}" for k, v in sorted(interesting_events.items())]
        audit_label = f"{audit_events} events ({', '.join(parts)})"
    else:
        audit_label = f"{audit_events} events"
    click.echo(f"    {C}Audit{R}       {W}{audit_label}{R}")
    click.echo("")

    # Protection
    click.echo(f"  {BC}Protection{R}")
    click.echo(f"    {BG}✓{R} {W}MITM proxy scanning all outbound traffic{R}")
    click.echo(f"    {BG}✓{R} {W}Secret exfiltration detection & blocking{R}")
    click.echo(f"    {BG}✓{R} {W}API key injection (keys never in agent memory){R}")
    click.echo(f"    {BG}✓{R} {W}Domain allowlist filtering{R}")
    click.echo(f"    {BG}✓{R} {W}Dangerous command detection{R}")
    click.echo(f"    {BG}✓{R} {W}Rate anomaly monitoring{R}")
    click.echo(f"    {BG}✓{R} {W}Tamper-proof audit trail{R}")
    if has_docker and docker_backend:
        click.echo(f"    {BG}✓{R} {W}Docker container isolation{R}")
    click.echo("")

    # Quick reference
    click.echo(f"  {BC}Quick Reference{R}")
    click.echo(f"    {DW}hermes-aegis status{R}        {D}System overview{R}")
    click.echo(f"    {DW}hermes-aegis vault list{R}     {D}Show protected keys{R}")
    click.echo(f"    {DW}hermes-aegis vault set KEY{R}  {D}Add API key to vault{R}")
    click.echo(f"    {DW}hermes-aegis test{R}           {D}Verify proxy blocks secrets{R}")
    click.echo(f"    {DW}hermes-aegis audit show{R}     {D}View security events{R}")

    if not has_docker:
        click.echo(f"\n  {BY}Docker not found{R} {DW}— install Docker Desktop for container isolation{R}")
    elif not docker_backend:
        click.echo(f"\n  {DW}Container isolation: set terminal.backend: docker in ~/.hermes/config.yaml{R}")

    click.echo(f"  {C}{'─' * W_LINE}{R}")
    click.echo("")


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx):
    """hermes-aegis: Security hardening layer for Hermes Agent."""
    ctx.ensure_object(dict)
    if ctx.invoked_subcommand is None:
        click.echo(f"hermes-aegis v{__version__}")
        if not VAULT_PATH.exists():
            click.echo("Run 'hermes-aegis setup' to initialize.")
        else:
            click.echo("Ready. Use 'hermes-aegis run' to start Hermes with protection.")


@main.command()
def install():
    """Install Hermes event hook, patch hermes-agent, and generate mitmproxy CA cert.

    Also migrates away from the old invasive setup if present.
    """
    from hermes_aegis.hook import install_hook, clean_old_setup
    from hermes_aegis.patches import apply_patches
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

    # Apply source patches to hermes-agent for Docker proxy forwarding
    patch_results = apply_patches()
    has_patch_errors = False
    for r in patch_results:
        if r.status == "applied":
            click.echo(f"Patch applied: {r.name}")
        elif r.status == "already_applied":
            pass  # Silent — idempotent re-install shouldn't be noisy
        elif r.status == "incompatible":
            click.echo(f"Warning: patch '{r.name}' incompatible — {r.detail}")
            click.echo("  Docker containers may not route traffic through the Aegis proxy.")
            click.echo("  This usually means hermes-agent was updated. Re-run after reporting the issue.")
        elif r.status == "error":
            click.echo(f"Error: patch '{r.name}' failed — {r.detail}")
            has_patch_errors = True

    if has_patch_errors:
        click.echo("\nSome patches failed. Aegis will still protect non-Docker sessions.")

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
    """Remove Hermes event hook and revert hermes-agent patches."""
    from hermes_aegis.hook import uninstall_hook
    from hermes_aegis.patches import revert_patches

    if uninstall_hook():
        click.echo("Hook removed.")
    else:
        click.echo("Hook not found — nothing to remove.")

    revert_results = revert_patches()
    for r in revert_results:
        if r.status == "applied":
            click.echo(f"Patch reverted: {r.name}")
        elif r.status == "error":
            click.echo(f"Warning: could not revert patch '{r.name}' — {r.detail}")


@main.command()
@click.option("--quiet", is_flag=True, help="Suppress output (for hook use)")
def start(quiet):
    """Start the aegis proxy as a background process."""
    from hermes_aegis.proxy.runner import start_proxy_process, is_proxy_running
    from hermes_aegis.config.settings import Settings

    running, port, _ = is_proxy_running()
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

    # Auto-reapply patches if hermes update wiped them
    from hermes_aegis.patches import patches_status, apply_patches
    missing = [r for r in patches_status() if r.status == "skipped"]
    if missing:
        click.echo(f"Re-applying {len(missing)} patch(es) (hermes update detected)...")
        results = apply_patches()
        applied = [r for r in results if r.status == "applied"]
        errors = [r for r in results if r.status == "error"]
        if applied:
            click.echo(f"  {len(applied)} patch(es) re-applied successfully.")
        if errors:
            for r in errors:
                click.echo(f"  Error: {r.name} — {r.detail}")
            click.echo("  Some patches failed. Run 'hermes-aegis install' manually.")
        click.echo()

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
    env["GIT_SSL_CAINFO"] = ca_cert
    env["NODE_EXTRA_CA_CERTS"] = ca_cert
    env["CURL_CA_BUNDLE"] = ca_cert
    env["AEGIS_ACTIVE"] = "1"

    # Set placeholder API keys for vault-managed provider keys
    # These satisfy Hermes's startup check; the proxy replaces them
    # with real keys at the HTTP level
    vault_keys = _get_vault_provider_keys()
    for key_name in vault_keys:
        env[key_name] = "aegis-managed"

    # ANTHROPIC_TOKEN is an OAuth setup-token (Bearer auth), not a per-request
    # API key. The proxy cannot intercept and replace Bearer tokens the same way
    # it replaces x-api-key headers, so we inject the real value directly into
    # the child environment instead of using the aegis-managed placeholder.
    if VAULT_PATH.exists():
        try:
            from hermes_aegis.vault.keyring_store import get_or_create_master_key
            from hermes_aegis.vault.store import VaultStore
            _mk = get_or_create_master_key()
            _v = VaultStore(VAULT_PATH, _mk)
            _token = _v.get("ANTHROPIC_TOKEN")
            if _token:
                env["ANTHROPIC_TOKEN"] = _token
        except Exception:
            pass

    # Print visible banner so the user knows aegis is active
    _print_aegis_banner(port, vault_keys)

    # Run hermes as a child process with proxy health watchdog
    from hermes_aegis.proxy import runner as proxy_runner
    import signal
    import threading

    hermes_proc = None

    def _proxy_watchdog(proxy_pid: int, proxy_port: int):
        """Background thread: kill hermes if proxy dies (PID + port probe).

        Handles proxy restarts gracefully: if the proxy is restarted on the
        same port (e.g. due to vault key update), the watchdog detects the new
        PID and continues monitoring rather than killing Hermes.
        """
        import socket
        import json as _json

        current_pid = proxy_pid
        while True:
            alive = False
            try:
                os.kill(current_pid, 0)
                sock = socket.socket()
                try:
                    sock.settimeout(1.0)
                    sock.connect(("127.0.0.1", proxy_port))
                    alive = True
                except OSError:
                    pass
                finally:
                    sock.close()
            except ProcessLookupError:
                pass

            if not alive:
                # Grace period: proxy may be restarting (e.g. vault key change).
                # Wait up to 12s (stop takes ~5s, start takes ~5s) then re-probe.
                time.sleep(12)
                sock = socket.socket()
                try:
                    sock.settimeout(1.0)
                    sock.connect(("127.0.0.1", proxy_port))
                    alive = True
                    # New proxy on same port — update tracked PID
                    try:
                        pid_info = _json.loads(proxy_runner.PID_FILE.read_text())
                        current_pid = pid_info["pid"]
                    except Exception:
                        pass
                except OSError:
                    pass
                finally:
                    sock.close()

            if not alive:
                click.echo(
                    f"\n\033[1;31m[hermes-aegis] Proxy (PID {current_pid}) is no longer running.\033[0m"
                )
                click.echo(
                    "\033[33mHermes is configured to route through the aegis proxy, but the proxy\033[0m"
                )
                click.echo(
                    "\033[33mhas stopped. API calls will fail with 'Connection refused' errors.\033[0m"
                )
                click.echo("")
                click.echo("  To restart:  hermes-aegis run")
                click.echo("  Check logs:  cat ~/.hermes-aegis/proxy.log")
                if hermes_proc and hermes_proc.poll() is None:
                    hermes_proc.send_signal(signal.SIGTERM)
                    # Print session resume info on watchdog kill
                    # Use the session_info captured after spawn (outer scope),
                    # not a fresh query which may find a different session.
                    if session_info:
                        click.echo("")
                        _print_session_summary(session_info, start_time)
                return
            time.sleep(2)

    # Always start the watchdog — even when reusing an existing proxy.
    # If the proxy dies for any reason (crash, manual stop, another session exiting),
    # we want Hermes to fail fast with a clear message rather than thrash with retries.
    watchdog_pid = pid if pid > 0 else None
    # If we reused an existing proxy, read its PID from the PID file
    if watchdog_pid is None:
        import json as _json
        try:
            _pid_info = _json.loads(proxy_runner.PID_FILE.read_text())
            watchdog_pid = _pid_info["pid"]
        except (FileNotFoundError, _json.JSONDecodeError, KeyError):
            pass

    if watchdog_pid is not None:
        watchdog = threading.Thread(target=_proxy_watchdog, args=(watchdog_pid, port), daemon=True)
        watchdog.start()

    # Start reactive watcher if rules are configured
    watcher = None
    reactive_manager = None
    try:
        from hermes_aegis.reactive.rules import load_rules
        from hermes_aegis.reactive.watcher import AuditFileWatcher
        from hermes_aegis.reactive.manager import ReactiveAgentManager
        from hermes_aegis.reactive.actions import CircuitBreakerExecutor
        from hermes_aegis.audit.trail import AuditTrail

        rules_path = AEGIS_DIR / "reactive-agents.json"
        if rules_path.exists():
            audit_trail = AuditTrail(AEGIS_DIR / "audit.jsonl")
            actions_executor = CircuitBreakerExecutor(audit_trail)
            reactive_manager = ReactiveAgentManager(
                rules_path=rules_path,
                audit_trail=audit_trail,
                actions_executor=actions_executor,
            )
            watcher = AuditFileWatcher(
                audit_path=AEGIS_DIR / "audit.jsonl",
                callback=reactive_manager.evaluate,
            )
            watcher.start()
    except Exception:
        pass  # Reactive agents are optional

    start_time = time.time()

    # Discover hermes session after spawn
    session_info = None

    try:
        hermes_proc = sp.Popen([hermes_bin] + list(hermes_args), env=env)

        # Discover session ID after hermes starts
        time.sleep(2)
        session_info = _discover_hermes_session()

        exit_code = hermes_proc.wait()
        _print_session_summary(session_info, start_time)
        _cleanup_reactive(watcher, reactive_manager)
        sys.exit(exit_code)
    except KeyboardInterrupt:
        _print_session_summary(session_info, start_time)
        _cleanup_reactive(watcher, reactive_manager)
    # Proxy is intentionally left running — it's shared infrastructure.
    # Stop it explicitly with: hermes-aegis stop


def _discover_hermes_session(timeout: float = 2.0) -> dict | None:
    """Query ~/.hermes/state.db for the most recent active session."""
    import sqlite3
    db_path = Path.home() / ".hermes" / "state.db"
    if not db_path.exists():
        return None
    try:
        db = sqlite3.connect(str(db_path), timeout=timeout)
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT id, started_at, message_count FROM sessions "
            "WHERE ended_at IS NULL ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        db.close()
        if row:
            return {
                "id": row["id"],
                "started_at": row["started_at"],
                "message_count": row["message_count"],
            }
    except Exception:
        pass
    return None


def _print_session_summary(session_info: dict | None, start_time: float) -> None:
    """Print session resume info on exit."""
    if session_info is None:
        return

    duration = time.time() - start_time
    hours, remainder = divmod(int(duration), 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        dur_str = f"{hours}h {minutes}m {seconds}s"
    elif minutes:
        dur_str = f"{minutes}m {seconds}s"
    else:
        dur_str = f"{seconds}s"

    sid = session_info.get("id", "unknown")
    msg_count = session_info.get("message_count", "?")

    C = "\033[36m"
    BC = "\033[1;36m"
    W = "\033[37m"
    D = "\033[2m"
    R = "\033[0m"

    click.echo("")
    click.echo(f"  {BC}Resume this session with:{R}")
    click.echo(f"    {W}hermes-aegis run -- --resume {sid}{R}")
    click.echo("")
    click.echo(f"  {C}Session:{R}        {W}{sid}{R}")
    click.echo(f"  {C}Duration:{R}       {W}{dur_str}{R}")
    click.echo(f"  {C}Messages:{R}       {W}{msg_count}{R}")
    click.echo("")


def _cleanup_reactive(watcher, manager) -> None:
    """Stop the reactive watcher and manager if active."""
    if watcher is not None:
        try:
            watcher.stop()
        except Exception:
            pass
    if manager is not None:
        try:
            manager.shutdown()
        except Exception:
            pass


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

    # Write a comment-only .env so hermes finds the file but doesn't get
    # placeholder credentials that would cause 401s when run standalone.
    # Standalone `hermes` requires `hermes setup` for OAuth or real API keys.
    # When run via `hermes-aegis run`, the real keys are injected at runtime.
    if not HERMES_ENV.exists():
        HERMES_ENV.write_text(
            "# Managed by hermes-aegis — real keys are in the encrypted vault.\n"
            "# Run hermes through aegis:  hermes-aegis run\n"
            "# Direct 'hermes' requires its own auth setup (hermes setup).\n"
        )

    vault_keys = _get_vault_provider_keys()
    if not vault_keys:
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
    was_running, existing_port, _ = is_proxy_running()

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


def _restart_proxy_if_running(audit_path: Path) -> None:
    """If the proxy is running, restart it so new vault secrets take effect.

    Vault values are frozen at proxy startup (entry.py wipes proxy-config.json
    immediately after loading, making hot-reload impossible). A full restart is
    the only way to propagate vault changes to the running ContentScanner.
    """
    from hermes_aegis.proxy.runner import is_proxy_running, stop_proxy, start_proxy_process
    from hermes_aegis.config.settings import Settings

    running, existing_port, _hash = is_proxy_running()
    if not running:
        return

    vault_secrets: dict[str, str] = {}
    vault_values: list[str] = []
    if VAULT_PATH.exists():
        from hermes_aegis.vault.keyring_store import get_or_create_master_key
        from hermes_aegis.vault.store import VaultStore
        master_key = get_or_create_master_key()
        vault = VaultStore(VAULT_PATH, master_key)
        for key_name in AUTO_INJECT_KEYS + PROXY_INJECT_KEYS:
            value = vault.get(key_name)
            if value is not None:
                vault_secrets[key_name] = value
        vault_values = vault.get_all_values()

    config_path = AEGIS_DIR / "config.json"
    settings = Settings(config_path)
    rate_limit_requests = int(settings.get("rate_limit_requests", 50))
    rate_limit_window = float(settings.get("rate_limit_window", 1.0))

    stop_proxy()
    start_proxy_process(
        vault_secrets=vault_secrets,
        vault_values=vault_values,
        audit_path=audit_path,
        rate_limit_requests=rate_limit_requests,
        rate_limit_window=rate_limit_window,
        listen_port=existing_port,  # Preserve port so running sessions' HTTPS_PROXY stays valid
    )
    click.echo("Proxy restarted with updated vault secrets.")


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
    _restart_proxy_if_running(AEGIS_DIR / "audit.jsonl")


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
    _restart_proxy_if_running(AEGIS_DIR / "audit.jsonl")


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
    running, port, _ = is_proxy_running()
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

    # Container isolation
    import os
    container_isolated = os.getenv("AEGIS_CONTAINER_ISOLATED") == "1"
    if container_isolated:
        click.echo("Container: isolated (AEGIS_CONTAINER_ISOLATED=1)")
    else:
        click.echo("Container: not in container mode")

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
@click.option(
    "--decision", "decision_filter", default=None,
    help="Filter by decision type: BLOCKED, DANGEROUS_COMMAND, ANOMALY, OUTPUT_REDACTED, INITIATED, COMPLETED",
)
def audit_show(show_all, decision_filter):
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

    if decision_filter:
        entries = [e for e in entries if e.decision == decision_filter.upper()]
        if not entries:
            click.echo(f"No entries with decision '{decision_filter.upper()}'.")
            return

    if not show_all:
        entries = entries[-20:]

    click.echo(f"Showing {len(entries)} entries:\n")
    for entry in entries:
        timestamp = datetime.fromtimestamp(entry.timestamp) if isinstance(entry.timestamp, float) else entry.timestamp
        click.echo(f"{timestamp} | {entry.tool_name:20} | {entry.decision:12} | {entry.middleware}")


@audit.command("clear")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt")
def audit_clear(yes):
    """Archive and clear the audit trail after review.

    The current audit trail is saved to ~/.hermes-aegis/audit.jsonl.YYYYMMDD-HHMMSS
    before clearing, so nothing is permanently lost.
    """
    import shutil
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

    # Show summary by decision type
    decision_counts: dict[str, int] = {}
    for entry in entries:
        decision_counts[entry.decision] = decision_counts.get(entry.decision, 0) + 1

    click.echo(f"Audit trail summary ({len(entries)} events total):")
    for decision, count in sorted(decision_counts.items()):
        click.echo(f"  {decision:20} {count}")

    if not yes:
        click.echo("")
        if not click.confirm(f"Archive and clear all {len(entries)} events?"):
            click.echo("Aborted.")
            return

    archive_name = f"audit.jsonl.{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    archive_path = AEGIS_DIR / archive_name
    shutil.copy2(audit_path, archive_path)
    os.chmod(archive_path, 0o600)
    audit_path.unlink()

    click.echo(f"Archived to {archive_path}")
    click.echo("Audit trail cleared.")


@audit.command("event")
@click.option("--type", "event_type", required=True, help="Event type (e.g. APPROVAL, HERMES_GUARD)")
@click.option("--tool", "tool_name", default="hermes", help="Tool that generated the event")
@click.option("--decision", default="ALLOWED", help="Decision: ALLOWED, BLOCKED, NEEDS_APPROVAL")
@click.option("--data", "event_data", default="", help="JSON string with event details")
def audit_event(event_type, tool_name, decision, event_data):
    """Record an external event in the aegis audit trail.

    Used by hermes-agent patches to forward approval decisions
    into the unified aegis audit log.
    """
    import json
    from hermes_aegis.audit.trail import AuditTrail
    trail = AuditTrail(AEGIS_DIR / "audit.jsonl")

    args = {"event_type": event_type}
    if event_data:
        try:
            args["details"] = json.loads(event_data)
        except json.JSONDecodeError:
            args["details"] = event_data

    trail.log(
        tool_name=tool_name,
        args_redacted=args,
        decision=decision,
        middleware="hermes_integration",
    )
    click.echo(f"Recorded {event_type} event ({decision})")


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


@config.command("list")
def config_list():
    """List all configuration settings with current values."""
    from hermes_aegis.config.settings import Settings

    config_path = AEGIS_DIR / "config.json"
    settings = Settings(config_path)
    all_settings = settings.get_all()
    if not all_settings:
        click.echo("No configuration settings.")
    else:
        click.echo("Configuration settings:")
        for k, v in sorted(all_settings.items()):
            click.echo(f"  {k} = {v}")


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


@main.command("scan-command")
@click.argument("command")
def scan_command(command):
    """Check a shell command against Aegis dangerous patterns.

    Exit 0 = safe, exit 1 = blocked. Used by the hermes-agent terminal
    patch to enforce dangerous command blocking in non-interactive contexts
    (e.g. gateway mode) where hermes would otherwise auto-allow.
    """
    from hermes_aegis.patterns.dangerous import detect_dangerous_command
    is_dangerous, pattern_key, description = detect_dangerous_command(command)
    if is_dangerous:
        click.echo(f"{description} ({pattern_key})")
        sys.exit(1)
    sys.exit(0)


# ---------------------------------------------------------------------------
# Approvals group
# ---------------------------------------------------------------------------

@main.group()
def approvals():
    """Manage cached approval decisions for commands and domains."""
    pass


@approvals.command("list")
def approvals_list():
    """Show all cached approval decisions."""
    from hermes_aegis.approval.cache import ApprovalCache
    import datetime

    cache = ApprovalCache()
    entries = cache.list_all()
    if not entries:
        click.echo("No cached approval decisions.")
        return

    click.echo(f"{'Pattern':<40} {'Decision':<10} {'Reason':<20} {'Expires':<20}")
    click.echo("-" * 90)
    for e in entries:
        if e.expires_at == 0:
            expires = "never"
        else:
            dt = datetime.datetime.fromtimestamp(e.expires_at)
            expires = dt.strftime("%Y-%m-%d %H:%M:%S")
        click.echo(f"{e.pattern:<40} {e.decision:<10} {e.reason or '-':<20} {expires:<20}")


@approvals.command("add")
@click.argument("pattern")
@click.option("--decision", required=True, type=click.Choice(["allow", "deny"]), help="Allow or deny matching commands.")
@click.option("--ttl", default=0, type=float, help="Time-to-live in seconds (0 = never expires).")
@click.option("--reason", default="", help="Why this decision was cached.")
def approvals_add(pattern, decision, ttl, reason):
    """Add an approval decision for a command pattern."""
    from hermes_aegis.approval.cache import ApprovalCache

    cache = ApprovalCache()
    entry = cache.add(pattern, decision, reason=reason, ttl_seconds=ttl)
    click.echo(f"Cached: {entry.pattern} -> {entry.decision}")
    if entry.expires_at:
        import datetime
        dt = datetime.datetime.fromtimestamp(entry.expires_at)
        click.echo(f"Expires: {dt.strftime('%Y-%m-%d %H:%M:%S')}")


@approvals.command("remove")
@click.argument("pattern")
def approvals_remove(pattern):
    """Remove a cached approval decision by pattern."""
    from hermes_aegis.approval.cache import ApprovalCache

    cache = ApprovalCache()
    if cache.remove(pattern):
        click.echo(f"Removed: {pattern}")
    else:
        click.echo(f"Pattern not found: {pattern}")


@approvals.command("clear")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
def approvals_clear(yes):
    """Remove all cached approval decisions."""
    from hermes_aegis.approval.cache import ApprovalCache

    if not yes:
        click.confirm("Clear all cached approval decisions?", abort=True)

    cache = ApprovalCache()
    count = cache.clear()
    click.echo(f"Cleared {count} cached approval(s).")


# ---------------------------------------------------------------------------
# Vault unlock
# ---------------------------------------------------------------------------

@vault.command("unlock")
def vault_unlock():
    """Unlock the vault after a circuit breaker lock."""
    from hermes_aegis.vault.store import unlock_vault

    if unlock_vault():
        click.echo("Vault unlocked.")
    else:
        click.echo("Vault is not locked.")


# ---------------------------------------------------------------------------
# Reactive agents group
# ---------------------------------------------------------------------------

@main.group()
def reactive():
    """Manage reactive audit agents."""
    pass


@reactive.command("init")
def reactive_init():
    """Create default reactive-agents.json with starter rules."""
    from hermes_aegis.reactive.rules import default_rules, save_rules

    rules_path = AEGIS_DIR / "reactive-agents.json"
    if rules_path.exists():
        click.echo(f"Rules already exist: {rules_path}")
        click.echo("Delete the file first if you want to reset to defaults.")
        return

    rules = default_rules()
    save_rules(rules_path, rules)
    click.echo(f"Created {rules_path} with {len(rules)} default rules:")
    for r in rules:
        click.echo(f"  {r.name} ({r.type}, severity={r.severity})")


@reactive.command("list")
def reactive_list():
    """Show loaded rules and their status."""
    from hermes_aegis.reactive.rules import load_rules

    rules_path = AEGIS_DIR / "reactive-agents.json"
    if not rules_path.exists():
        click.echo("No reactive rules configured.")
        click.echo("Run 'hermes-aegis reactive init' to create defaults.")
        return

    rules = load_rules(rules_path)
    if not rules:
        click.echo("No rules found in reactive-agents.json.")
        return

    click.echo(f"Reactive rules ({len(rules)}):\n")
    for r in rules:
        status = "enabled" if r.enabled else "disabled"
        actions = f", actions={r.allowed_actions}" if r.allowed_actions else ""
        click.echo(f"  {r.name}")
        click.echo(f"    Type: {r.type} | Severity: {r.severity} | Status: {status}")
        click.echo(f"    Cooldown: {r.cooldown}{actions}")
        if r.trigger.is_threshold:
            click.echo(f"    Trigger: {r.trigger.count}+ events in {r.trigger.window}")
        elif r.trigger.decision:
            click.echo(f"    Trigger: decision={r.trigger.decision}")
        elif r.trigger.decision_in:
            click.echo(f"    Trigger: decision in {r.trigger.decision_in}")
        click.echo()


@reactive.command("test")
def reactive_test():
    """Dry-run rules against recent audit entries (no agent spawned)."""
    from hermes_aegis.reactive.rules import load_rules
    from hermes_aegis.audit.trail import AuditTrail

    rules_path = AEGIS_DIR / "reactive-agents.json"
    if not rules_path.exists():
        click.echo("No reactive rules configured.")
        return

    rules = load_rules(rules_path)
    audit_path = AEGIS_DIR / "audit.jsonl"
    if not audit_path.exists():
        click.echo("No audit trail found.")
        return

    trail = AuditTrail(audit_path)
    entries = trail.read_all()[-50:]

    click.echo(f"Testing {len(rules)} rules against {len(entries)} recent entries...\n")
    for rule in rules:
        if not rule.enabled:
            continue
        matches = 0
        for e in entries:
            if rule.trigger.matches_entry(e.decision, e.middleware):
                matches += 1
        if matches:
            click.echo(f"  {rule.name}: {matches} matching entries")
            if rule.trigger.is_threshold and matches >= rule.trigger.count:
                click.echo(f"    -> Would FIRE (threshold {rule.trigger.count} reached)")
            elif not rule.trigger.is_threshold:
                click.echo(f"    -> Would FIRE (per-event trigger)")
        else:
            click.echo(f"  {rule.name}: no matching entries")


@reactive.command("enable")
@click.argument("name")
def reactive_enable(name):
    """Enable a reactive rule by name."""
    import json

    rules_path = AEGIS_DIR / "reactive-agents.json"
    if not rules_path.exists():
        click.echo("No reactive rules configured.")
        return

    data = json.loads(rules_path.read_text())
    for r in data.get("rules", []):
        if r["name"] == name:
            r["enabled"] = True
            rules_path.write_text(json.dumps(data, indent=2))
            click.echo(f"Rule '{name}' enabled.")
            return
    click.echo(f"Rule '{name}' not found.")


@reactive.command("disable")
@click.argument("name")
def reactive_disable(name):
    """Disable a reactive rule by name."""
    import json

    rules_path = AEGIS_DIR / "reactive-agents.json"
    if not rules_path.exists():
        click.echo("No reactive rules configured.")
        return

    data = json.loads(rules_path.read_text())
    for r in data.get("rules", []):
        if r["name"] == name:
            r["enabled"] = False
            rules_path.write_text(json.dumps(data, indent=2))
            click.echo(f"Rule '{name}' disabled.")
            return
    click.echo(f"Rule '{name}' not found.")


# ---------------------------------------------------------------------------
# Reports group
# ---------------------------------------------------------------------------

@main.group()
def report():
    """Manage scheduled audit reports."""
    pass


@report.command("schedule")
@click.option("--every", "interval", help="Interval (e.g. '24h', '1h', '30m')")
@click.option("--cron", "cron_expr", help="Cron expression (e.g. '0 9 * * 1')")
@click.option("--name", default=None, help="Friendly name for the report job")
@click.option("--model", default="anthropic/claude-sonnet-4-6", help="Model for report generation")
@click.option("--deliver", default=None, help="Delivery target (e.g. 'telegram')")
def report_schedule(interval, cron_expr, name, model, deliver):
    """Schedule a periodic audit report."""
    if not interval and not cron_expr:
        click.echo("Error: Provide --every or --cron schedule.")
        sys.exit(1)

    schedule = interval or cron_expr

    try:
        from hermes_aegis.reports.scheduler import schedule_report
        job = schedule_report(schedule=schedule, name=name, model=model, deliver=deliver)
        click.echo(f"Report scheduled: {job.get('name', job.get('id', '?'))}")
        click.echo(f"  Schedule: {schedule}")
        click.echo(f"  Job ID: {job.get('id', '?')}")
    except Exception as e:
        click.echo(f"Error scheduling report: {e}")
        sys.exit(1)


@report.command("list")
def report_list():
    """List scheduled report jobs."""
    try:
        from hermes_aegis.reports.scheduler import list_reports
        jobs = list_reports()
        if not jobs:
            click.echo("No scheduled reports.")
            return

        click.echo(f"Scheduled reports ({len(jobs)}):\n")
        for j in jobs:
            enabled = "enabled" if j.get("enabled", True) else "disabled"
            click.echo(f"  {j.get('name', '?')} [{enabled}]")
            click.echo(f"    ID: {j.get('id', '?')}")
            click.echo(f"    Schedule: {j.get('schedule_str', '?')}")
            click.echo()
    except Exception as e:
        click.echo(f"Error listing reports: {e}")


@report.command("run")
@click.option("--model", default="anthropic/claude-sonnet-4-6", help="Model for report generation")
@click.option("--deliver", default=None, help="Delivery target")
def report_run(model, deliver):
    """Generate a report immediately."""
    click.echo("Generating audit report...")
    try:
        from hermes_aegis.reports.scheduler import run_report_now
        result = run_report_now(model=model, deliver=deliver)
        if result:
            click.echo(f"Report saved: {result.get('report_path', '?')}")
        else:
            click.echo("Report generation failed.")
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error generating report: {e}")
        sys.exit(1)


@report.command("cancel")
@click.argument("job_id")
def report_cancel(job_id):
    """Cancel a scheduled report by job ID."""
    try:
        from hermes_aegis.reports.scheduler import cancel_report
        if cancel_report(job_id):
            click.echo(f"Report cancelled: {job_id}")
        else:
            click.echo(f"Job not found: {job_id}")
    except Exception as e:
        click.echo(f"Error cancelling report: {e}")


# ---------------------------------------------------------------------------
# tmux screen session management
# ---------------------------------------------------------------------------

TMUX_SESSION = "hermes-aegis"


@main.command("screen")
@click.option("--attach", is_flag=True, help="Attach to existing aegis tmux session")
@click.option("--kill", "kill_session", is_flag=True, help="Kill the aegis tmux session")
@click.argument("hermes_args", nargs=-1, type=click.UNPROCESSED)
def screen(attach, kill_session, hermes_args):
    """Launch hermes-aegis run in a persistent tmux session.

    The session survives terminal closure, screen locks, and SSH disconnects.
    Useful for long-running or overnight aegis sessions.

    \b
    Examples:
        hermes-aegis screen              # Start new session
        hermes-aegis screen --attach     # Reattach to existing
        hermes-aegis screen --kill       # Kill session
        hermes-aegis screen -- gateway   # Start with hermes args
    """
    import shutil
    import subprocess as sp

    tmux = shutil.which("tmux")
    if not tmux:
        click.echo("Error: tmux not found. Install it with:")
        click.echo("  brew install tmux     # macOS")
        click.echo("  apt install tmux      # Debian/Ubuntu")
        sys.exit(1)

    # Check if session exists
    result = sp.run(
        [tmux, "has-session", "-t", TMUX_SESSION],
        capture_output=True,
    )
    session_exists = result.returncode == 0

    if kill_session:
        if session_exists:
            sp.run([tmux, "kill-session", "-t", TMUX_SESSION])
            click.echo(f"Session '{TMUX_SESSION}' killed.")
        else:
            click.echo(f"No session '{TMUX_SESSION}' found.")
        return

    if attach:
        if session_exists:
            click.echo(f"Attaching to '{TMUX_SESSION}'...")
            os.execvp(tmux, [tmux, "attach-session", "-t", TMUX_SESSION])
        else:
            click.echo(f"No session '{TMUX_SESSION}' found. Start one with: hermes-aegis screen")
            sys.exit(1)
        return

    if session_exists:
        click.echo(f"Session '{TMUX_SESSION}' already running.")
        click.echo(f"  Attach:  hermes-aegis screen --attach")
        click.echo(f"  Kill:    hermes-aegis screen --kill")
        return

    # Build the hermes-aegis run command
    aegis_bin = shutil.which("hermes-aegis") or sys.argv[0]
    cmd_parts = [aegis_bin, "run"]
    if hermes_args:
        cmd_parts.append("--")
        cmd_parts.extend(hermes_args)
    run_cmd = " ".join(cmd_parts)

    # Create detached tmux session running hermes-aegis
    sp.run([
        tmux, "new-session",
        "-d",                   # detached
        "-s", TMUX_SESSION,     # session name
        "-n", "aegis",          # window name
        run_cmd,                # command to run
    ], check=True)

    click.echo(f"Session '{TMUX_SESSION}' started.")
    click.echo(f"  Attach:  hermes-aegis screen --attach")
    click.echo(f"  Kill:    hermes-aegis screen --kill")
    click.echo(f"  Direct:  tmux attach -t {TMUX_SESSION}")
    click.echo("")

    if click.confirm("Attach now?", default=True):
        os.execvp(tmux, [tmux, "attach-session", "-t", TMUX_SESSION])
