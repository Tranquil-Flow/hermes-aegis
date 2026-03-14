# Zero-Touch Run Command Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `hermes-aegis run` command that wraps `hermes` with full proxy protection, and remove all code that modifies Hermes files (`~/.hermes/.env`, `config.yaml`, `docker.py`), so installing hermes-aegis never breaks or touches a user's existing Hermes setup.

**Architecture:** `hermes-aegis run` starts the mitmproxy proxy, builds a child environment with proxy vars (`HTTP_PROXY`, `HTTPS_PROXY`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`) and placeholder API keys (`KEY=aegis-managed`), then `exec`s `hermes` as a subprocess. When hermes exits, the proxy is stopped. No persistent modifications to any Hermes files. The hook at `~/.hermes/hooks/aegis-security/` is kept for gateway mode but becomes optional.

**Tech Stack:** Python 3.11+, Click CLI, mitmproxy, subprocess

**Key invariant:** `hermes-aegis setup`, `hermes-aegis install`, and `hermes-aegis uninstall` must NEVER write to, modify, or delete any file under `~/.hermes/`. Two exceptions: (1) the hook directory `~/.hermes/hooks/aegis-security/` which is a designed extension point, and (2) `clean_old_setup()` may remove `aegis-managed` placeholder entries from `~/.hermes/.env` as a one-time migration to undo damage from previous versions — after this migration, no code path writes to `.env` again.

---

## Background for the implementing agent

### How hermes-aegis works

hermes-aegis is a security layer for Hermes Agent. It runs a mitmproxy-based MITM proxy that:
- Scans all outbound HTTP for API keys/secrets and blocks exfiltration
- Injects real API keys from an encrypted vault into LLM provider requests at the HTTP level
- Rate-limits suspicious burst patterns
- Maintains a tamper-proof audit trail

### The problem being solved

Currently, `hermes-aegis install` modifies several Hermes files:
1. Writes `KEY=aegis-managed` placeholder values to `~/.hermes/.env` (so Hermes passes its startup check)
2. Modifies `~/.hermes/config.yaml` (adds CA cert volume mount)
3. Patches `~/.hermes/hermes-agent/tools/environments/docker.py` (forwards proxy env vars to containers)

This is invasive — if something goes wrong, it breaks Hermes. We want hermes-aegis to be a completely safe add-on.

### How the `run` command solves this

Instead of modifying Hermes files permanently, `hermes-aegis run` sets everything up transiently in the subprocess environment:
- Placeholder API keys are set as env vars (not written to `.env`)
- Proxy env vars are set as env vars (not requiring config changes)
- Hermes runs as a child process and inherits these env vars
- When hermes exits, the proxy stops and nothing is left behind

### How API key injection works

1. `hermes-aegis run` sets `OPENROUTER_API_KEY=aegis-managed` in the child environment
2. Hermes sees this env var and passes its `_has_any_provider_configured()` startup check
3. When Hermes makes an HTTP request to `openrouter.ai`, it sends `Authorization: Bearer aegis-managed`
4. The mitmproxy addon intercepts this and replaces it with `Authorization: Bearer sk-real-key-from-vault`
5. The real API key never enters Hermes's process memory

### Key files you'll work with

| File | Purpose |
|------|---------|
| `src/hermes_aegis/cli.py` | CLI commands — add `run`, modify `install`/`uninstall` |
| `src/hermes_aegis/hook.py` | Hook management — remove `configure_hermes_for_aegis`, `patch_hermes_docker_forwarding`, `unpatch_hermes_docker_forwarding` |
| `src/hermes_aegis/proxy/runner.py` | Proxy lifecycle — `start_proxy_process()`, `stop_proxy()`, `is_proxy_running()` |
| `src/hermes_aegis/proxy/injector.py` | API key injection into HTTP requests (READ ONLY — unchanged) |
| `tests/test_cli_commands.py` | CLI command tests |
| `tests/test_hook.py` | Hook management tests |
| `README.md` | User-facing docs |
| `CLAUDE.md` | Developer docs |

### Commands to run tests

```bash
uv run pytest tests/ -q                    # All tests
uv run pytest tests/test_cli_commands.py -v # CLI tests only
uv run pytest tests/test_hook.py -v         # Hook tests only
```

---

## Chunk 1: Add `run` command and clean up `install`

### Task 1: Write failing test for `run` command

**Files:**
- Create: `tests/test_run_command.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_run_command.py`:

```python
"""Tests for hermes-aegis run command."""
import json
import os
import pytest
from pathlib import Path
from click.testing import CliRunner
from unittest.mock import patch, MagicMock, call

from hermes_aegis.cli import main


class TestRunCommand:
    """Test the 'hermes-aegis run' command."""

    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.run")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_starts_proxy_and_hermes(
        self, mock_stop, mock_subproc, mock_vault_keys, mock_start, mock_find
    ):
        mock_subproc.return_value = MagicMock(returncode=0)

        runner = CliRunner()
        result = runner.invoke(main, ["run"])

        assert result.exit_code == 0
        mock_start.assert_called_once()
        mock_subproc.assert_called_once()
        mock_stop.assert_called_once()

        # Check env vars were set for the hermes subprocess
        call_kwargs = mock_subproc.call_args
        env = call_kwargs[1]["env"]
        assert env["HTTP_PROXY"] == "http://127.0.0.1:8443"
        assert env["HTTPS_PROXY"] == "http://127.0.0.1:8443"
        assert "REQUESTS_CA_BUNDLE" in env
        assert "SSL_CERT_FILE" in env
        assert env["OPENROUTER_API_KEY"] == "aegis-managed"

    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value=set())
    @patch("subprocess.run")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_works_with_empty_vault(
        self, mock_stop, mock_subproc, mock_vault_keys, mock_start, mock_find
    ):
        """Run should work even without vault keys (user may have their own)."""
        mock_subproc.return_value = MagicMock(returncode=0)

        runner = CliRunner()
        result = runner.invoke(main, ["run"])

        assert result.exit_code == 0
        # No aegis-managed placeholder keys should be injected
        env = mock_subproc.call_args[1]["env"]
        for key in ["OPENROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
            assert env.get(key) != "aegis-managed"

    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(-1, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.run")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_does_not_stop_preexisting_proxy(
        self, mock_stop, mock_subproc, mock_vault_keys, mock_start, mock_find
    ):
        """If proxy was already running, run should NOT stop it on exit."""
        mock_subproc.return_value = MagicMock(returncode=0)

        runner = CliRunner()
        result = runner.invoke(main, ["run"])

        assert result.exit_code == 0
        mock_stop.assert_not_called()

    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.run")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_passes_args_to_hermes(
        self, mock_stop, mock_subproc, mock_vault_keys, mock_start, mock_find
    ):
        mock_subproc.return_value = MagicMock(returncode=0)

        runner = CliRunner()
        result = runner.invoke(main, ["run", "--", "gateway", "status"])

        call_args = mock_subproc.call_args[0][0]
        assert call_args == ["/usr/bin/hermes", "gateway", "status"]

    @patch("hermes_aegis.cli._find_hermes_binary", return_value=None)
    def test_run_fails_if_hermes_not_found(self, mock_find):
        runner = CliRunner()
        result = runner.invoke(main, ["run"])
        assert result.exit_code == 1
        assert "hermes" in result.output.lower()

    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", side_effect=RuntimeError("port busy"))
    def test_run_fails_if_proxy_fails(self, mock_start, mock_find):
        runner = CliRunner()
        result = runner.invoke(main, ["run"])
        assert result.exit_code == 1
        assert "proxy" in result.output.lower() or "port" in result.output.lower()

    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.run")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_propagates_hermes_exit_code(
        self, mock_stop, mock_subproc, mock_vault_keys, mock_start, mock_find
    ):
        mock_subproc.return_value = MagicMock(returncode=42)

        runner = CliRunner()
        result = runner.invoke(main, ["run"])

        assert result.exit_code == 42

    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.run", side_effect=KeyboardInterrupt)
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_stops_proxy_on_interrupt(
        self, mock_stop, mock_subproc, mock_vault_keys, mock_start, mock_find
    ):
        runner = CliRunner()
        result = runner.invoke(main, ["run"])

        # Proxy should always be stopped, even on interrupt
        mock_stop.assert_called_once()

    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.run")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_does_not_modify_hermes_env_file(
        self, mock_stop, mock_subproc, mock_vault_keys, mock_start, mock_find, tmp_path
    ):
        """The run command must NEVER write to ~/.hermes/.env."""
        fake_env = tmp_path / ".env"
        fake_env.write_text("OPENROUTER_API_KEY=sk-real-key\n")
        original_content = fake_env.read_text()

        mock_subproc.return_value = MagicMock(returncode=0)

        with patch("hermes_aegis.cli.HERMES_ENV", fake_env):
            runner = CliRunner()
            result = runner.invoke(main, ["run"])

        # .env file must be completely untouched
        assert fake_env.read_text() == original_content
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_run_command.py -v`
Expected: FAIL — `run` command doesn't exist yet, helper functions don't exist

- [ ] **Step 3: Commit**

```bash
git add tests/test_run_command.py
git commit -m "test: add failing tests for hermes-aegis run command"
```

---

### Task 2: Implement the `run` command

**Files:**
- Modify: `src/hermes_aegis/cli.py`

The `run` command needs three helper functions and the command itself. Here's the implementation:

- [ ] **Step 1: Add helper functions to cli.py**

Add these three helper functions after the existing `_check_hermes_installed()` function (around line 25):

```python
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
```

- [ ] **Step 2: Add the `run` command**

Add this command after the `stop` command (after line 192):

```python
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

    # Set placeholder API keys for vault-managed provider keys
    # These satisfy Hermes's startup check; the proxy replaces them
    # with real keys at the HTTP level
    vault_keys = _get_vault_provider_keys()
    for key_name in vault_keys:
        env[key_name] = "aegis-managed"

    if vault_keys:
        click.echo(f"Aegis proxy active (port {port}) — protecting {len(vault_keys)} API keys")
    else:
        click.echo(f"Aegis proxy active (port {port}) — scanning traffic (no vault keys)")

    # Run hermes as a child process
    from hermes_aegis.proxy.runner import stop_proxy

    try:
        result = sp.run([hermes_bin] + list(hermes_args), env=env)
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        pass  # Normal exit via Ctrl+C
    finally:
        if we_started_proxy:
            stop_proxy()
```

- [ ] **Step 3: Add `import os` to the top of cli.py if not already present**

Check the imports at the top of `src/hermes_aegis/cli.py`. Add `import os` if missing (it's needed for `os.environ.copy()`). Currently the file imports `click`, `sys`, and `Path` — add `import os` after `import sys`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_run_command.py -v`
Expected: All 9 tests PASS

- [ ] **Step 5: Run full test suite**

Run: `uv run pytest tests/ -q`
Expected: All existing tests still pass

- [ ] **Step 6: Commit**

```bash
git add src/hermes_aegis/cli.py tests/test_run_command.py
git commit -m "feat: add hermes-aegis run command for zero-touch hermes wrapping"
```

---

### Task 3: Remove `.env` placeholder writing from `install`/`uninstall`

**Important:** Steps 1-6 are code changes — apply ALL of them before running tests at Step 7. Running tests mid-task will fail due to import mismatches between cli.py and hook.py.

**Files:**
- Modify: `src/hermes_aegis/cli.py`
- Modify: `tests/test_cli_commands.py`

- [ ] **Step 1: Write a test asserting `install` doesn't touch `.env`**

Add this test to `TestInstallCommand` in `tests/test_cli_commands.py`:

```python
    @patch("hermes_aegis.cli._check_hermes_installed", return_value=True)
    @patch("hermes_aegis.utils.ensure_mitmproxy_ca_cert")
    @patch("hermes_aegis.hook.clean_old_setup", return_value=[])
    @patch("hermes_aegis.hook.install_hook")
    def test_install_does_not_write_hermes_env(self, mock_install, mock_clean, mock_cert, mock_hermes, tmp_path):
        """Install must never write to ~/.hermes/.env."""
        mock_install.return_value = Path("/tmp/fake-hook")
        mock_cert.return_value = Path("/tmp/fake-cert.pem")

        fake_env = tmp_path / ".env"
        # Don't create the file — install should not create it either

        with patch("hermes_aegis.cli.HERMES_ENV", fake_env):
            runner = CliRunner()
            result = runner.invoke(main, ["install"])

        assert not fake_env.exists(), "install must not create ~/.hermes/.env"
```

- [ ] **Step 2: Remove placeholder logic from `install` command**

In `src/hermes_aegis/cli.py`, find the `install` command (around line 41). Replace the vault check block (lines 86-100) with a simpler vault status message:

Remove this block:
```python
    # Check vault and write placeholder keys to Hermes .env
    if not VAULT_PATH.exists():
        click.echo("\nNote: Vault not initialized. Run 'hermes-aegis setup' to add secrets.")
    elif _count_vault_secrets() == 0:
        click.echo("\nNote: Vault is empty. Add API keys with:")
        click.echo("  hermes-aegis vault set OPENAI_API_KEY")
        click.echo("  hermes-aegis vault set ANTHROPIC_API_KEY")
    else:
        written = _write_hermes_env_placeholders()
        if written:
            click.echo(f"Wrote placeholder keys to ~/.hermes/.env: {', '.join(written)}")
            click.echo("  (Real keys stay in the aegis vault — placeholders let Hermes start)")
```

Replace with:
```python
    # Vault status hint
    if not VAULT_PATH.exists():
        click.echo("\nNote: Vault not initialized. Run 'hermes-aegis setup' to add secrets.")
    elif _count_vault_secrets() == 0:
        click.echo("\nNote: Vault is empty. Add API keys with:")
        click.echo("  hermes-aegis vault set OPENROUTER_API_KEY")
```

- [ ] **Step 3: Update install closing message**

Replace the closing message (lines 99-100):
```python
    click.echo("\nDone. Hermes will now auto-start the aegis proxy on launch.")
    click.echo("Works with both local and docker backends.")
```
With:
```python
    click.echo("\nDone. Run Hermes with aegis protection:")
    click.echo("  hermes-aegis run")
```

- [ ] **Step 4: Remove placeholder logic from `uninstall` command**

In the `uninstall` command, remove these lines:
```python
    # Remove aegis-managed placeholder keys from .env
    removed = _remove_hermes_env_placeholders()
    if removed:
        click.echo(f"Removed placeholder keys from ~/.hermes/.env: {', '.join(removed)}")
```

Also remove the import of `_remove_hermes_env_placeholders` if it's only used here.

- [ ] **Step 5: Remove `configure_hermes_for_aegis` and docker patching from `install`**

In the `install` command, remove these lines:
```python
    # Configure Hermes for aegis (fix config, add CA cert volume)
    config_actions = configure_hermes_for_aegis()
    for action in config_actions:
        click.echo(f"Config: {action}")

    # Patch Docker env var forwarding so containers route through proxy
    if patch_hermes_docker_forwarding():
        click.echo("Docker: patched env var forwarding for proxy support")
```

And update the import at the top of the `install` function. Change:
```python
    from hermes_aegis.hook import (
        install_hook, clean_old_setup,
        patch_hermes_docker_forwarding, configure_hermes_for_aegis,
    )
```
To:
```python
    from hermes_aegis.hook import install_hook, clean_old_setup
```

Similarly in `uninstall`, remove the docker unpatching:
```python
    if unpatch_hermes_docker_forwarding():
        click.echo("Docker: removed proxy forwarding patch.")
```

And change its import from:
```python
    from hermes_aegis.hook import uninstall_hook, unpatch_hermes_docker_forwarding
```
To:
```python
    from hermes_aegis.hook import uninstall_hook
```

- [ ] **Step 6: Delete the helper functions that are no longer used**

Delete these functions from `cli.py`:
- `_write_hermes_env_placeholders()` (lines 655-714)
- `_remove_hermes_env_placeholders()` (lines 717-746)
- `_HERMES_PROVIDER_KEYS` set (lines 648-652) — **WAIT: keep this!** It's used by `_get_vault_provider_keys()` which you added in Task 2.

Actually, `_HERMES_PROVIDER_KEYS` IS still used by the new `_get_vault_provider_keys()`. Keep it. Only delete `_write_hermes_env_placeholders` and `_remove_hermes_env_placeholders`.

- [ ] **Step 7: Run tests**

Run: `uv run pytest tests/test_cli_commands.py -v`
Expected: All pass (including the new test)

Run: `uv run pytest tests/ -q`
Expected: All pass

- [ ] **Step 8: Commit**

```bash
git add src/hermes_aegis/cli.py tests/test_cli_commands.py
git commit -m "refactor: remove .env placeholder writing — run command handles keys transiently"
```

---

### Task 4: Remove Hermes-modifying functions from `hook.py`

**Prerequisite:** Task 3 must be fully complete before starting this task. Task 3 removes the imports of `configure_hermes_for_aegis`, `patch_hermes_docker_forwarding`, and `unpatch_hermes_docker_forwarding` from `cli.py`. This task deletes those functions from `hook.py`. If you delete them before removing the imports, you'll get ImportErrors.

**Files:**
- Modify: `src/hermes_aegis/hook.py`

- [ ] **Step 1: Delete `configure_hermes_for_aegis()` from hook.py**

Remove the entire `configure_hermes_for_aegis()` function (lines 292-338). This function modifies `~/.hermes/config.yaml`.

- [ ] **Step 2: Delete `patch_hermes_docker_forwarding()` from hook.py**

Remove the entire function (lines 213-254). This modifies `~/.hermes/hermes-agent/tools/environments/docker.py`.

- [ ] **Step 3: Delete `unpatch_hermes_docker_forwarding()` from hook.py**

Remove the entire function (lines 257-289).

- [ ] **Step 4: Clean up unused imports in hook.py**

Note: Do NOT remove `pyyaml` from `pyproject.toml` — it's still used by `src/hermes_aegis/vault/migrate.py` for parsing Hermes's `config.yaml` during vault migration.

After deleting the three functions, check if any imports at the top of `hook.py` are now unused. The `HERMES_AGENT_DIR` constant is only used by `patch_hermes_docker_forwarding` and `unpatch_hermes_docker_forwarding` and `clean_old_setup`. Check if `clean_old_setup` still uses it — yes it does (line 198). So keep `HERMES_AGENT_DIR`.

The `PROXY_ENV_VARS` list (lines 15-18) is no longer used by any function in hook.py. Delete it.

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/test_hook.py -v`
Expected: All pass (these tests only cover install/uninstall/is_installed/clean_old_setup)

Run: `uv run pytest tests/ -q`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add src/hermes_aegis/hook.py
git commit -m "refactor: remove hermes-modifying functions from hook.py"
```

---

### Task 5: Update status command and README

**Files:**
- Modify: `src/hermes_aegis/cli.py` (status command)
- Modify: `README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update `status` command output**

The status command should mention `hermes-aegis run` instead of implying the hook auto-starts things. No code change needed in the status logic itself — but update the `main()` no-command output.

In the `main()` function, change:
```python
        click.echo("Ready. Use 'hermes-aegis install' to set up the Hermes hook.")
```
To:
```python
        click.echo("Ready. Use 'hermes-aegis run' to start Hermes with protection.")
```

- [ ] **Step 2: Update README.md Quick Start**

Read the current README.md first. Then update the Quick Start section. Replace:
```markdown
# 5. Use Hermes normally — proxy starts automatically
hermes
```
With:
```markdown
# 5. Run Hermes with aegis protection
hermes-aegis run
```

- [ ] **Step 3: Update README.md "How It Works" section**

Replace the current "How It Works" section (lines 73-83) with:
```markdown
### How It Works

1. `hermes-aegis run` starts the mitmproxy-based security proxy
2. Sets `HTTP_PROXY`/`HTTPS_PROXY` env vars so all traffic routes through the proxy
3. Sets placeholder API keys (`aegis-managed`) that satisfy Hermes's startup check
4. Runs `hermes` as a child process — all subprocess calls inherit the proxy env vars
5. Proxy scans for secrets, blocks exfiltration, injects real API keys from the vault
6. When Hermes exits, the proxy is stopped automatically

No monkey-patching. No shell modifications. No file modifications. Just a proxy.
```

- [ ] **Step 4: Update README.md "How Hermes sees your keys" callout**

Replace:
```markdown
> **How Hermes sees your keys:** During `hermes-aegis install`, placeholder values (`aegis-managed`) are written to `~/.hermes/.env` so Hermes passes its startup check. The proxy then injects real keys at the HTTP level — they never appear in process memory or environment variables.
```
With:
```markdown
> **How Hermes sees your keys:** When you run `hermes-aegis run`, placeholder values (`aegis-managed`) are set as environment variables so Hermes passes its startup check. The proxy then injects real keys at the HTTP level. Your `~/.hermes/.env` file is never modified.
```

- [ ] **Step 5: Update README CLI Reference**

Add the `run` command to the CLI Reference section (after `hermes-aegis install`):
```markdown
hermes-aegis run                 # Run Hermes with aegis protection
hermes-aegis run -- gateway      # Run Hermes gateway with protection
```

- [ ] **Step 6: Update CLAUDE.md**

In `CLAUDE.md`, update the Architecture section. Replace:
```markdown
- **Hermes hook** at `~/.hermes/hooks/aegis-security/` auto-starts proxy on `gateway:startup`, stops on `gateway:shutdown`
```
With:
```markdown
- **`hermes-aegis run`** starts proxy, wraps `hermes` with proxy env vars, stops proxy on exit
- **Hermes hook** at `~/.hermes/hooks/aegis-security/` available for gateway mode (optional)
```

Add to the Commands section:
```bash
uv run hermes-aegis run              # Run Hermes with aegis protection
```

- [ ] **Step 7: Run full test suite**

Run: `uv run pytest tests/ -q`
Expected: All pass

- [ ] **Step 8: Commit**

```bash
git add src/hermes_aegis/cli.py README.md CLAUDE.md
git commit -m "docs: update README and CLI for hermes-aegis run workflow"
```

---

### Task 6: Clean up existing `.env` placeholders (one-time migration)

**Files:**
- Modify: `src/hermes_aegis/hook.py`
- Modify: `tests/test_hook.py`

**Intentional invariant exception:** This is the only code that modifies `~/.hermes/.env` — it removes `aegis-managed` placeholders that previous versions of hermes-aegis wrote. This is a one-time migration to undo past damage. After cleanup runs, no code path ever writes to `.env` again. This exception is documented in the key invariant at the top of this plan.

The user's `~/.hermes/.env` currently has `aegis-managed` placeholders from a previous install. The `install` command cleans these up via `clean_old_setup()`, which already handles shell rc files and sitecustomize.py.

- [ ] **Step 1: Add `.env` placeholder cleanup to `clean_old_setup()` in hook.py**

Add this block at the end of `clean_old_setup()` in `hook.py`, before the `return actions` line:

```python
    # Clean aegis-managed placeholder keys from ~/.hermes/.env
    hermes_env = HERMES_DIR / ".env"
    if hermes_env.exists():
        try:
            lines = hermes_env.read_text().splitlines()
            new_lines = []
            cleaned_keys = []
            for line in lines:
                stripped = line.strip()
                if "=aegis-managed" in stripped:
                    key = stripped.split("=", 1)[0]
                    cleaned_keys.append(key)
                    continue
                new_lines.append(line)

            # Remove header if that's all that's left
            if all(l.strip().startswith("#") or not l.strip() for l in new_lines):
                new_lines = []

            if cleaned_keys:
                if new_lines:
                    hermes_env.write_text("\n".join(new_lines) + "\n")
                else:
                    hermes_env.unlink()
                actions.append(f"Removed aegis-managed placeholders from .env: {', '.join(cleaned_keys)}")
        except Exception:
            pass
```

- [ ] **Step 2: Add test for `.env` cleanup**

Add to `TestCleanOldSetup` in `tests/test_hook.py`:

```python
    def test_cleans_aegis_managed_env(self, tmp_path):
        hermes_dir = tmp_path / ".hermes"
        hermes_dir.mkdir()
        env_file = hermes_dir / ".env"
        env_file.write_text(
            "# Managed by hermes-aegis\n"
            "OPENROUTER_API_KEY=aegis-managed\n"
            "OPENAI_API_KEY=aegis-managed\n"
        )

        with patch("hermes_aegis.hook.HERMES_DIR", hermes_dir):
            with patch("hermes_aegis.hook.Path.home", return_value=tmp_path):
                actions = clean_old_setup()

        # File should be deleted (only had aegis-managed entries + comment)
        assert not env_file.exists()
        assert any("aegis-managed" in a for a in actions)

    def test_preserves_real_keys_in_env(self, tmp_path):
        hermes_dir = tmp_path / ".hermes"
        hermes_dir.mkdir()
        env_file = hermes_dir / ".env"
        env_file.write_text(
            "OPENROUTER_API_KEY=sk-real-key-123\n"
            "OPENAI_API_KEY=aegis-managed\n"
        )

        with patch("hermes_aegis.hook.HERMES_DIR", hermes_dir):
            with patch("hermes_aegis.hook.Path.home", return_value=tmp_path):
                actions = clean_old_setup()

        # File should still exist with real key preserved
        assert env_file.exists()
        content = env_file.read_text()
        assert "sk-real-key-123" in content
        assert "aegis-managed" not in content
```

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/test_hook.py -v`
Expected: All pass

Run: `uv run pytest tests/ -q`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add src/hermes_aegis/hook.py tests/test_hook.py
git commit -m "feat: clean up aegis-managed .env placeholders during migration"
```

---

## Chunk 2: Verification and edge cases

### Task 7: Manual verification checklist

These are manual checks the implementing agent should perform after all code changes are complete.

- [ ] **Step 1: Verify `hermes-aegis install` doesn't touch `.env`**

```bash
# Back up and remove any existing .env
cp ~/.hermes/.env ~/.hermes/.env.bak 2>/dev/null || true
rm ~/.hermes/.env 2>/dev/null || true

# Run install
uv tool install -e ~/Projects/hermes-aegis --force
hermes-aegis install

# Verify .env was NOT created
ls -la ~/.hermes/.env 2>&1  # Should say "No such file"

# Restore backup
cp ~/.hermes/.env.bak ~/.hermes/.env 2>/dev/null || true
```

- [ ] **Step 2: Verify `hermes-aegis run` starts hermes with proxy**

```bash
hermes-aegis run
# Expected: See "Aegis proxy active (port XXXX)" message, then Hermes splash screen
# Ctrl+C to exit — proxy should stop automatically
```

- [ ] **Step 3: Verify `hermes-aegis status` after run exits**

```bash
hermes-aegis status
# Expected: Proxy: stopped (not running after hermes exit)
```

- [ ] **Step 4: Verify existing `hermes` command still works independently**

```bash
# If user has their own keys in .env, hermes should work without aegis
hermes
# Expected: Normal Hermes startup (no aegis involvement)
```

- [ ] **Step 5: Run full test suite one final time**

```bash
uv run pytest tests/ -q
# Expected: All tests pass
```

- [ ] **Step 6: Commit any fixes from verification**

Only if issues were found during manual verification.

---

## Summary of changes

| File | Change |
|------|--------|
| `src/hermes_aegis/cli.py` | Add `run` command + helpers, remove `.env` writing from install/uninstall, remove docker patch calls |
| `src/hermes_aegis/hook.py` | Delete `configure_hermes_for_aegis`, `patch_hermes_docker_forwarding`, `unpatch_hermes_docker_forwarding`, `PROXY_ENV_VARS`; add `.env` cleanup to `clean_old_setup` |
| `tests/test_run_command.py` | New — 9 tests for the run command |
| `tests/test_cli_commands.py` | Add test asserting install doesn't write `.env` |
| `tests/test_hook.py` | Add tests for `.env` placeholder cleanup |
| `README.md` | Update Quick Start, How It Works, CLI Reference |
| `CLAUDE.md` | Update Architecture section |

## What is NOT changed

- `src/hermes_aegis/proxy/` — all proxy code (addon, entry, runner, injector, server) unchanged
- `src/hermes_aegis/patterns/` — all detection patterns unchanged
- `src/hermes_aegis/vault/` — vault storage unchanged
- `src/hermes_aegis/audit/` — audit trail unchanged
- `src/hermes_aegis/config/` — settings/allowlist unchanged
- `src/hermes_aegis/middleware/` — middleware chain unchanged
- All existing tests for patterns, vault, audit, proxy, middleware unchanged

## Docker backend note

This plan removes Docker-specific Hermes modifications (`patch_hermes_docker_forwarding`, `configure_hermes_for_aegis`). Docker containers spawned by Hermes won't automatically route through the aegis proxy. This is acceptable because:
1. The `local` backend (user's current setup) works perfectly with `hermes-aegis run`
2. Docker support requires upstream changes to Hermes (env var forwarding) — not something aegis should monkey-patch
3. If Docker support is needed later, it should be a PR to hermes-agent, not a source code patch
