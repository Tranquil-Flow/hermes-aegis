# Hermes Aegis - Autonomous Work Prompts

**Purpose**: Templates for scheduling autonomous work sessions

---

## Model B: Continuous Until Blocker (Recommended)

Use this template for scheduling me to work through multiple chunks autonomously.

### For Chunks 3-5 (After Chunk 2 Test)

```python
schedule_cronjob(
    prompt="""
AUTONOMOUS WORK: Complete hermes-aegis Chunks 3-5

PROJECT: /Users/evinova/Projects/hermes-aegis
GOAL: Implement remaining chunks until blocked or complete

CURRENT STATE:
- Chunks 1-2 complete
- Test count: ~29 tests passing
- Working from main branch
- All previous work committed, not pushed

═══════════════════════════════════════════════════════════════
CHUNKS TO IMPLEMENT
═══════════════════════════════════════════════════════════════

CHUNK 3 (Tasks 8-10): Middleware Chain
- Task 8: Middleware chain core
- Task 9: Secret redaction middleware  
- Task 10: Audit trail middleware

CHUNK 4 (Tasks 11-13b): Tier 2 Container + Proxy
- Task 11: Docker container builder
- Task 12: Container runner
- Task 13: MITM proxy injector + scanner
- Task 13b: mitmproxy addon

CHUNK 5 (Tasks 14-20): Integration
- Task 14: Integrity checking
- Task 15: Anomaly monitor
- Task 16: Outbound scanner (Tier 1 monkey-patch)
- Task 17: Audit viewer
- Task 18: Hermes registry hook
- Task 19: Full CLI with run command
- Task 20: Full test suite + verification

═══════════════════════════════════════════════════════════════
APPROACH
═══════════════════════════════════════════════════════════════

For each chunk:
1. Read relevant section from docs/IMPLEMENTATION-PLAN.md
2. For each task in the chunk:
   - Use delegate_task with full context from plan
   - Verify implementation follows TDD (tests first, then code)
   - Run tests: python3 -m pytest [test_file] -v
   - Verify tests pass
   - Commit with suggested message from plan
3. After each CHUNK completes:
   - Run full test suite: python3 -m pytest tests/ -v
   - If all passing: continue to next chunk
   - If failures: try to fix, if can't fix after 2 attempts → STOP and report
4. Keep working through chunks 3 → 4 → 5 sequentially

═══════════════════════════════════════════════════════════════
STOPPING CONDITIONS
═══════════════════════════════════════════════════════════════

STOP IMMEDIATELY IF:
✋ Test failures I can't fix after 2 attempts
✋ Plan is ambiguous on a critical detail
✋ Hit error I don't understand
✋ Chunk 4 Docker/mitmproxy integration seems unclear
✋ Successfully complete all chunks (report success!)

═══════════════════════════════════════════════════════════════
DECISION-MAKING AUTHORITY
═══════════════════════════════════════════════════════════════

CAN DECIDE:
✓ Code style (follow existing Hermes patterns)
✓ Variable naming
✓ Minor implementation details within task spec
✓ Test fixture design

CANNOT DECIDE (must stop and ask):
✋ Change architecture from plan
✋ Skip tests or security features
✋ Add features not in plan
✋ Alternative approaches when plan is specific

IF UNCERTAIN: Analyze pros/cons, make best judgment, FLAG for review in report.

═══════════════════════════════════════════════════════════════
CRITICAL RULES
═══════════════════════════════════════════════════════════════
🚫 NEVER git push to GitHub
🚫 Only touch files inside /Users/evinova/Projects/hermes-aegis
✅ Commit after each task
✅ Run pytest to verify before claiming success
✅ Use subagents to keep context clean

═══════════════════════════════════════════════════════════════
EXPECTED OUTPUT
═══════════════════════════════════════════════════════════════

Report when done or blocked:

STATUS: [COMPLETED / BLOCKED / NEEDS_DECISION]

COMPLETED TASKS:
- Task 6: ✓ 11 tests passing
- Task 7: ✓ 4 tests passing
(or)
- Task X: ✓ Complete
- Task Y: ⚠️ BLOCKED - [reason]

TOTAL TESTS: X passing
COMMITS: [list commit hashes and messages]
DECISIONS MADE: [list or "None"]
BLOCKERS: [description if blocked, or "None"]

═══════════════════════════════════════════════════════════════

Begin immediately upon job start.
""",
    schedule="2m",
    deliver="origin"
)
