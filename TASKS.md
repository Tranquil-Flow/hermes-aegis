# Hermes-Aegis Tasks

## Phase 1: Verify v0.2.0 Compatibility ✓ COMPLETE

Hermes Agent was updated to v0.2.0 (2026.3.12). Verify Aegis still works.

- [x] Run full test suite: `uv run pytest tests/ -q` — 186 tests pass ✓
- [x] Verify integration.py monkey-patch works with v0.2.0's `_create_environment()` - signature matches ✓
- [x] Verify `AegisEnvironment` still correctly wraps `_LocalEnvironment` and `_DockerEnvironment` ✓
- [x] Integration tests all pass ✓

## Phase 2: New Security Features ✓ COMPLETE

Design principle: everything works secure by default, user can fine-tune for more security.

- [x] **Domain allowlist** — 33 tests pass ✓
  - Created config/allowlist.py with DomainAllowlist class
  - CLI commands: hermes-aegis allowlist add/remove/list
  - Proxy checks allowlist before forwarding
  - Empty allowlist = allow all (default, no breakage)

- [x] **Output secret scanning** — 34 tests pass ✓
  - Created middleware/output_scanner.py
  - Wired into default middleware chain (post-dispatch)
  - On by default, redacts secrets in subprocess output
  - Uses existing scan_for_secrets()

- [x] **Workspace file write scanning** — 24 tests pass, 2 skipped ✓
  - Created tier1/file_scanner.py
  - Monkey-patches builtins.open for Tier 1
  - On by default, logs violations to audit trail
  - Warns user when secrets written to files

- [x] **Dangerous command blocking** — 36 tests pass ✓
  - Created config/settings.py and middleware/dangerous_blocker.py
  - CLI commands: hermes-aegis config get/set
  - Off by default (audit-only, backward compatible)
  - Enable blocking: hermes-aegis config set dangerous_commands block

- [x] **Network rate limiting** — 14 tests pass ✓
  - Updated proxy/addon.py with sliding-window rate limiter
  - On by default (50 requests / 1 second threshold)
  - Per-host tracking, logs anomalies to audit trail
  - Configurable: hermes-aegis config set rate_limit_requests N

**Result:** 144 new tests added, 330 total tests passing, 0 regressions

## Phase 3: Validation 🔄 IN PROGRESS

- [x] Run full test suite — 330/330 tests pass ✓
- [ ] Test with live Hermes Agent in real usage
- [ ] Run red team attacks if Docker available
- [ ] Update demo scripts for new features
- [ ] Update README with new features
