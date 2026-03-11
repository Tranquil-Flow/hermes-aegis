from __future__ import annotations

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.proxy.injector import inject_api_key, is_llm_provider_request
from hermes_aegis.proxy.server import ContentScanner


class ArmorAddon:
    """Inject API keys for trusted LLM hosts and block secret exfiltration elsewhere."""

    def __init__(
        self,
        vault_secrets: dict[str, str],
        vault_values: list[str],
        audit_trail: AuditTrail | None = None,
    ) -> None:
        self._vault_secrets = vault_secrets
        self._scanner = ContentScanner(vault_values=vault_values)
        self._audit = audit_trail

    def request(self, flow) -> None:
        host = flow.request.host
        path = flow.request.path

        if is_llm_provider_request(host, path):
            new_headers = inject_api_key(host, path, dict(flow.request.headers), self._vault_secrets)
            for key, value in new_headers.items():
                flow.request.headers[key] = value
            return

        body = flow.request.get_content() or b""
        body_text = body.decode("utf-8", errors="replace")
        blocked, reason = self._scanner.scan_request(
            url=flow.request.url,
            body=body_text,
            headers=dict(flow.request.headers),
        )
        if not blocked:
            return

        if self._audit is not None:
            self._audit.log(
                tool_name="outbound_http",
                args_redacted={"host": host, "path": path, "reason": reason},
                decision="BLOCKED",
                middleware="ProxyContentScanner",
            )
        flow.kill()
