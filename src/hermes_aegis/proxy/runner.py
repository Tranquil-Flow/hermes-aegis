from __future__ import annotations

import threading

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.proxy.addon import ArmorAddon


def start_proxy(
    vault_secrets: dict[str, str],
    vault_values: list[str],
    audit_trail: AuditTrail,
    listen_port: int = 8443,
) -> threading.Thread:
    """Start the MITM proxy in a background thread."""

    def _run() -> None:
        from mitmproxy.options import Options
        from mitmproxy.tools.dump import DumpMaster

        addon = ArmorAddon(
            vault_secrets=vault_secrets,
            vault_values=vault_values,
            audit_trail=audit_trail,
        )
        options = Options(listen_port=listen_port, ssl_insecure=True)
        master = DumpMaster(options)
        master.addons.add(addon)
        master.run()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread
