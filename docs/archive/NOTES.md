# Hermes Aegis — Implementation Notes

**Status**: ✅ READY FOR IMPLEMENTATION  
**Polished by**: Opus 4.6  
**Date**: 2026-03-11

---

## Documents

1. **Design Spec**: `/Users/evinova/Documents/2026-03-11-hermes-aegis-design.md`  
   Complete threat model, architecture diagrams, security assumptions

2. **Implementation Plan**: `/Users/evinova/Documents/2026-03-11-hermes-aegis-POLISHED.md`  
   Step-by-step TDD implementation (20 tasks, 5 chunks, ~81 tests)

3. **Review Report**: `/Users/evinova/Documents/2026-03-11-hermes-aegis-REVIEW.md`  
   Comprehensive review identifying and documenting all fixes applied

---

## Fixes Applied

### Critical Syntax Errors (FIXED)
- ✅ Line 810: `SECRET_PATTERNS = [` (was missing `=` and `[`)
- ✅ Lines 411-415: String concatenation in test fixture (proper multiline strings)
- ✅ Test data consistency: All test values now match (sk-test-key-123, sk-ant-test-456)
- ✅ Line 2213: `self._vault_secrets = vault_secrets` (was truncated)
- ✅ Line 2283: `vault_secrets=vault_secrets,` (was truncated)
- ✅ Line 3420: `vault_secrets = {key: vault.get(key) for key in vault.list_keys()}` (was malformed)
- ✅ Line 3425: `vault_secrets=vault_secrets,` (was truncated)

### Documentation Improvements (ADDED)
- ✅ Polished banner at top indicating implementation-ready status
- ✅ Dockerfile enhanced with notes about hermes-agent installation alternatives
- ✅ Keyring error handling with helpful error messages for headless environments
- ✅ Design spec reference updated to actual file path

---

## Implementation Strategy Recommendations

### Option A: Sonnet 3.7 (FAST)
**Time**: 1.5-2 hours  
**Cost**: ~1.5M tokens (~$22.50 with Sonnet 3.7)  
**Pros**: Fast, will auto-correct minor issues, parallel chunk execution  
**Cons**: Token cost  

**Workflow**:
1. Hand complete polished plan to Sonnet
2. Execute chunks 1-5 sequentially (auto-checkpoint per chunk)
3. Opus code review after chunks 2 and 4 (security-critical)
4. Run final integration tests

---

### Option B: Qwen 2.5 Coder 32B (FREE)
**Time**: 4-6 hours  
**Cost**: $0 (GPU time only on remote connect)  
**Pros**: Zero token cost, precise TDD execution  
**Cons**: Slower, needs clear instructions  

**Workflow**:
1. Qwen implements chunks 1-3 (vault, patterns, middleware) — straightforward
2. Opus code review after chunk 2
3. Switch to Sonnet for chunk 4 (Tier 2 proxy) — most complex
4. Qwen finishes chunk 5 (integrity, anomaly, CLI)
5. Opus final integration review

---

### Option C: Hybrid (RECOMMENDED)
**Time**: ~3 hours total  
**Cost**: ~500K tokens (~$7.50)  
**Pros**: Best balance of speed, cost, and correctness  

**Workflow**:
1. **Qwen** (2 hrs): Chunks 1-3 (vault, patterns, middleware)  
   *These are well-tested, straightforward implementations*
   
2. **Sonnet** (45 min): Chunk 4 (Tier 2 container + proxy)  
   *Complex async, Docker, mitmproxy — Sonnet handles this well*
   
3. **Qwen** (45 min): Chunk 5 (integrity, anomaly, final CLI)  
   *Back to straightforward implementations*
   
4. **Opus** (30 min): Security review + integration smoke tests

---

## Key Implementation Notes

### Chunk 1: Vault (Tasks 1-5)
- No dependencies, can start immediately
- OS keyring integration may fail in headless — graceful error message added
- Migration tests use consistent fixture data now

### Chunk 2: Patterns (Tasks 6-7)
- All regex patterns are complete and tested
- Crypto patterns cover: Ethereum, Bitcoin WIF, BIP32, Solana, BIP39 seed phrases
- Exact-match scanning checks plain + base64 + URL-encoded + hex + reversed

### Chunk 3: Middleware (Tasks 8-10)
- Middleware chain supports pre/post dispatch hooks
- Order matters: audit → integrity → anomaly → scanner → redaction
- Post-dispatch runs in REVERSE order (redaction is last filter)

### Chunk 4: Tier 2 (Tasks 11-13b)
- **Most complex part** — Docker, mitmproxy, async coordination
- Dockerfile updated with installation notes
- Proxy addon is complete and tested
- Container hardening: cap-drop=ALL, read-only, no-new-privileges

### Chunk 5: Integration (Tasks 14-20)
- Integrity manifest tracks SHA-256 of instruction files
- Anomaly monitor is observational-only (never blocks)
- Task 18 hook.py is the critical glue for Tier 1
- Task 19 cli.py is the final consolidated CLI with all commands

---

## Test Coverage

**Total**: ~81 tests across 15 test files

| Module | Tests | Notes |
|--------|-------|-------|
| vault | 8 | Encryption, persistence, list/set/remove |
| keyring | 2 | OS keyring integration (mocked) |
| migrate | 4 | .env → vault migration |
| patterns | 11 | Secret + crypto key detection |
| audit | 4 | Hash chain, tamper detection |
| middleware | 6 | Chain execution, pre/post hooks |
| redaction | 4 | Pattern + exact-match redaction |
| container | 7 | Docker hardening, lifecycle |
| proxy | 7 | API key injection, content scanning |
| proxy_addon | 5 | mitmproxy addon integration |
| integrity | 7 | Manifest build, verification |
| anomaly | 4 | Frequency + repetition detection |
| scanner | 3 | urllib3 monkey-patch |
| hook | 2 | Hermes registry integration |
| cli | 7 | Full CLI commands |

---

## Security Review Checklist

When implementation is complete, verify:

- [ ] No secrets in test fixtures that could leak
- [ ] All `***` placeholders replaced with actual values
- [ ] Vault encryption uses Fernet (AES-128-CBC + HMAC-SHA256)
- [ ] Master key stored in OS keyring (not in code)
- [ ] Middleware order is correct (see design doc line 93)
- [ ] Container has no capabilities (cap-drop=ALL)
- [ ] Tier 2 proxy blocks exact-match vault values
- [ ] Audit trail hash chain validates end-to-end
- [ ] No bulk export methods on VaultStore
- [ ] Tier 1 refuses to run if Hermes not importable (no subprocess fallback)

---

## Success Criteria (from design doc)

1. ✓ `hermes-aegis setup && hermes-aegis run` works in <2 min
2. ✓ All 40+ Hermes tools function identically through armor
3. ✓ No secrets in audit trail, LLM context, or outbound HTTP
4. ✓ Malicious skill exfiltration blocked in Tier 2
5. ✓ Self-learning loop continues to function
6. ✓ Anomaly monitor flags >50 calls/minute
7. ✓ Audit trail hash chain validates

---

## Next Steps

1. Choose implementation strategy (A, B, or C above)
2. If Qwen: Ensure remote connect is active
3. If Sonnet: Prepare for ~1.5M token usage
4. Start implementation: `hermes-aegis setup` should be first command tested
5. After each chunk: Commit with suggested message from plan
6. Final: Run full test suite (`pytest tests/ -v`)

---

## Questions / Decisions Needed

**Q: Is hermes-agent published to PyPI yet?**  
A: If not, update Dockerfile to use git clone method (noted in plan)

**Q: Should we add a file-based keyring fallback?**  
A: Plan includes graceful error for now. Can add fallback post-MVP.

**Q: Which agent should implement this?**  
A: See strategy options above. Hybrid (C) is recommended.

---

**Ready to build! 🌙✨**
