# Autonomous Research Notes

This file contains review/research notes only. No items below were implemented in this session.

## Improvement ideas
- Add direct tests for `DispatchDecision.NEEDS_APPROVAL` semantics in `MiddlewareChain` so the intended behavior is explicit before Tier 1 integration work.
- Add explicit tests for `SecretRedactionMiddleware` non-string passthrough and crypto-key redaction paths.
- Add tests for `ensure_network()` behavior in `src/hermes_aegis/container/builder.py`, including the already-exists path and the create-network path.
- Add tests for `ContainerRunner.is_running` and the `docker SDK is not installed` error path.
- Add tests for `start_proxy()` that patch `mitmproxy` objects, so the thread bootstrap path is exercised without requiring a live proxy.
- Add end-to-end Tier 2 verification once later tasks are in place: build image, start proxy, run a sample request path, and verify audit entries.

## Risks / limitations observed
- `src/hermes_aegis/proxy/runner.py` is only unit-tested indirectly through addon logic; there is no live mitmproxy startup verification in this session.
- `src/hermes_aegis/container/runner.py` was only exercised with mocked Docker objects; no real Docker daemon interaction was verified in this session.
- `src/hermes_aegis/container/Dockerfile` assumes `hermes-agent` is installable with `pip install hermes-agent`; that assumption was not checked in this session.
- The current review pass confirms `python3 -m pytest tests/ -q` is green, but it does not prove Tier 2 works end-to-end or that any future Tier 1 hook/CLI integration is correct.
- `OVERNIGHT-RUN-PROMPT.md` remains untracked in the repository; I did not modify or commit it.

## Suggested next implementation focus
1. Task 14: integrity manifest + middleware
2. Task 15: anomaly monitor
3. Task 16: outbound content scanner middleware
4. Task 17: audit viewer
5. Task 18: Hermes registry hook
6. Task 19: final consolidated CLI
7. Task 20: final verification
