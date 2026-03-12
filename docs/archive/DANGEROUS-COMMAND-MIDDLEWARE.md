# Dangerous Command Middleware Integration Analysis

## Executive Summary

**Should we integrate dangerous command detection as middleware?**

**Answer: NO - It's already better implemented in Hermes Agent core.**

Hermes Agent has a mature, well-designed dangerous command approval system that operates at the **tool layer**, which is the right place for it. Adding middleware would be **redundant and inferior**.

---

## What Hermes Agent Already Has

### Built-in Dangerous Command System

**Location**: `~/.hermes/hermes-agent/tools/approval.py` + `terminal_tool.py`

**Features**:
1. **50+ dangerous patterns** - rm -rf, SQL DROP, fork bombs, etc.
2. **Three approval scopes**:
   - Once: This command only
   - Session: All matching commands this session
   - Always: Save to permanent allowlist in config
3. **Thread-safe per-session state** - Multiple concurrent agents supported
4. **Config persistence** - Allowlist saved to `config.yaml`
5. **CLI + Gateway integration** - Works in interactive and async messaging modes
6. **Pattern-based** - Regex matching with descriptions

**Example patterns**:
```python
DANGEROUS_PATTERNS = [
    (r'\\brm\\s+(-[^\\s]*\\s+)*/', "delete in root path"),
    (r'\\bDROP\\s+(TABLE|DATABASE)\\b', "SQL DROP"),
    (r'\\b(curl|wget)\\b.*\\|\\s*(ba)?sh\\b', "pipe remote content to shell"),
    (r':()\\s*{\\s*:\\s*\\|\\s*:&\\s*}\\s*;:', "fork bomb"),
]
```

### How It Works

```
terminal(command="rm -rf /")
    ↓
terminal_tool._check_dangerous_command()
    ↓
approval.detect_dangerous_command()
    ↓
approval.prompt_dangerous_approval()
    ↓
user chooses [once|session|always|deny]
    ↓
command executes OR blocked
```

**Key insight**: Operates at **tool call level**, sees the actual command string before execution.

---

## Why NOT Add Dangerous Command Middleware?

### 1. **Wrong Layer**

**Middleware operates on tool dispatch**:
- Sees: `{tool: "terminal", args: {"command": "rm -rf /"}}`
- After: Tool resolution, before execution

**Terminal tool operates on command execution**:
- Sees: Actual command string
- After: Args parsed
- Before: Shell execution

**Problem**: Terminal tool checks command AFTER middleware chain. Adding middleware would make TWO checks:
1. Middleware (generic, doesn't know terminal semantics)
2. Terminal tool (specialized, knows command structure)

**Result**: Redundant, confusing, possibly conflicting approvals.

### 2. **Other Tools Need Different Patterns**

Dangerous commands are **tool-specific**:

**Terminal**: `rm -rf /`, `curl | sh`
**File write**: Overwriting `/etc/passwd`, `.ssh/authorized_keys`
**Browser**: navigate to `file:///etc/passwd`
**SQL**: `DROP DATABASE; --`

**Middleware is tool-agnostic**: It can't know what "dangerous" means for each tool.

**Better**: Each tool implements its own safety checks (terminal already does).

### 3. **Approval UX is Complex**

The existing system has:
- Interactive prompts (CLI)
- Async messages (Gateway)
- Timeouts
- Session state
- Config persistence

**Middleware can't replicate this** without:
- Duplicating all that code
- Breaking the existing terminal tool flow
- Handling context (who's the user? what session?)

### 4. **NEEDS_APPROVAL is for Middleware Logic**

`DispatchDecision.NEEDS_APPROVAL` exists for **middleware-level decisions**:
- Rate limiting ("too many calls, need approval")
- Cost estimates ("this will cost $10, approve?")
- Policy violations ("accessing sensitive data")

**Not for tool-specific validation** like "this terminal command is dangerous".

---

## Where Middleware DOES Make Sense

Our existing middleware is correctly placed:

| Middleware | Purpose | Why Middleware Layer |
|------------|---------|---------------------|
| AuditTrailMiddleware | Log all tool calls | Cross-tool concern |
| RedactionMiddleware | Scan args for secrets | Cross-tool concern |
| (Future) RateLimitMiddleware | Prevent spam | Cross-tool concern |
| (Future) CostEstimateMiddleware | Budget control | Cross-tool concern |

**Pattern**: Middleware is for **concerns that apply to ALL tools**.

Dangerous commands are **tool-specific**, so they belong in tools.

---

## Could We Still Add It? (Don't)

### Hypothetical Implementation

```python
class DangerousCommandMiddleware(ToolMiddleware):
    PATTERNS = [
        r'rm\\s+-rf',
        r'docker\\s+(build|run)',
        # ... Duplicate from tools/approval.py
    ]
    
    def pre_dispatch(self, name, args, context):
        if name == "terminal":
            cmd = args.get("command", "")
            for pattern in self.PATTERNS:
                if re.search(pattern, cmd):
                    # Problem: How to prompt user?
                    # Problem: Duplicates terminal_tool logic
                    return DispatchDecision.NEEDS_APPROVAL
        return DispatchDecision.ALLOW
```

### Why This is Bad

1. **Duplicates patterns** - Now two sources of truth (middleware + terminal_tool)
2. **Can't handle approval flow** - Middleware doesn't have approval.py's session state
3. **Breaks existing system** - Users who configured terminal allowlist won't understand why it still prompts
4. **Out of order** - Middleware runs BEFORE tool has command context
5. **No benefit** - Terminal tool already does this better

---

## Recommendation

### ✅ DO THIS

**Integrate with Hermes' existing system at the audit level**:

```python
class AuditTrailMiddleware(ToolMiddleware):
    def pre_dispatch(self, name, args, context):
        # Log that a command will be checked by terminal tool
        if name == "terminal":
            from tools.approval import detect_dangerous_command
            cmd = args.get("command", "")
            is_dangerous, pattern, desc = detect_dangerous_command(cmd)
            if is_dangerous:
                self._trail.log(
                    tool_name=name,
                    args_redacted={"command": "[DANGEROUS]"},
                    decision="FLAGGED_DANGEROUS",
                    description=desc
                )
        return DispatchDecision.ALLOW
```

**Benefits**:
- Doesn't interfere with terminal tool's approval flow
- Records dangerous commands in audit trail
- Can analyze patterns later (security review)
- Works alongside existing system

### ❌ DON'T DO THIS

- Add dangerous command detection to middleware (redundant)
- Duplicate approval patterns (two sources of truth)
- Try to replicate approval UX in middleware (wrong layer)

---

## Could Other Tools Benefit from Middleware?

### File Tool

**Dangerous writes**: `/etc/passwd`, `.ssh/authorized_keys`, `.hermes/.env`

**Current**: File tool doesn't check anything dangerous
**Could add**: File blacklist middleware

**Better**: Add to file tool itself (same reason as terminal)

### Browser Tool

**Dangerous navigations**: `file:///`, internal network IPs, credential theft sites

**Current**: No protection
**Could add**: URL blacklist middleware

**Better**: Add to browser tool itself

### General Pattern

**Tool-specific safety belongs in tools, not middleware.**

Middleware is for **cross-cutting concerns** (logging, secrets, rate limits).

---

## Integration with Hermes-Aegis

### Current Design is Correct

**Hermes-Aegis middleware**:
- ✅ AuditTrailMiddleware (logging - cross-tool)
- ✅ RedactionMiddleware (secrets - cross-tool)
- ✅ Future: RateLimitMiddleware (spam prevention - cross-tool)

**Hermes Agent tools**:
- ✅ terminal_tool (dangerous commands - terminal-specific)
- ❌ file_tool (doesn't check dangerous writes - TODO for Hermes)
- ❌ browser_tool (doesn't check dangerous URLs - TODO for Hermes)

**Aegis should NOT duplicate what Hermes does better at the tool layer.**

### What Aegis SHOULD Add

**If we want to enhance dangerous command detection**:

1. **Audit integration** (see code above) - log dangerous commands
2. **Secret detection in commands** - already doing this for HTTP
3. **Documentation** - point users to Hermes' `command_allowlist` config

**Not**: Rebuild approval system in middleware.

---

## Conclusion

**Q: Should we integrate dangerous command middleware?**
**A: No. Hermes already has a better implementation.**

**Why Hermes' implementation is superior**:
1. Operates at the right layer (tool execution, not dispatch)
2. Mature approval UX (3 scopes, persistence, async support)
3. 50+ patterns already tuned
4. Thread-safe session management
5. Config integration

**What Aegis should do instead**:
1. Document that Hermes has this feature
2. Optionally: Add audit trail logging for dangerous commands
3. Focus on what Aegis does uniquely (secret scanning, container isolation)

**Design principle**: Don't duplicate what the platform already does well.
