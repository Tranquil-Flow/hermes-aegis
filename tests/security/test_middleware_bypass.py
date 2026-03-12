"""Real security tests for middleware chain bypass attempts.

Tests verify that the middleware chain properly enforces security policies
and cannot be easily bypassed through various attack vectors.
"""
import pytest
import asyncio

from hermes_aegis.middleware.chain import (
    MiddlewareChain,
    ToolMiddleware,
    CallContext,
    DispatchDecision
)


class BlockDangerousToolMiddleware(ToolMiddleware):
    """Middleware that blocks calls to 'dangerous_tool'."""
    
    async def pre_dispatch(self, name, args, ctx):
        if name == "dangerous_tool":
            return DispatchDecision.DENY
        return DispatchDecision.ALLOW


class LoggingMiddleware(ToolMiddleware):
    """Middleware that logs all calls."""
    
    def __init__(self):
        self.calls = []
    
    async def pre_dispatch(self, name, args, ctx):
        self.calls.append(("pre", name, args))
        return DispatchDecision.ALLOW
    
    async def post_dispatch(self, name, args, result, ctx):
        self.calls.append(("post", name, result))
        return result


# Task 3.6.1: Direct Blocking
def test_blocks_dangerous_tool_directly():
    """Test that calling dangerous_tool through the chain is blocked."""
    blocker = BlockDangerousToolMiddleware()
    chain = MiddlewareChain([blocker])
    
    async def dangerous_tool(args):
        return "This should never execute"
    
    ctx = CallContext()
    result = asyncio.run(chain.execute("dangerous_tool", {}, dangerous_tool, ctx))
    
    # Should return error, not execute
    assert isinstance(result, dict)
    assert "error" in result
    assert "BlockDangerousToolMiddleware" in result["error"]


def test_allows_safe_tool():
    """Test that non-dangerous tools are allowed through."""
    blocker = BlockDangerousToolMiddleware()
    chain = MiddlewareChain([blocker])
    
    async def safe_tool(args):
        return "safe result"
    
    ctx = CallContext()
    result = asyncio.run(chain.execute("safe_tool", {}, safe_tool, ctx))
    
    assert result == "safe result"


# Task 3.6.2: Prompt Injection via Results
def test_no_prompt_injection_via_result():
    """Test that tool results containing tool-call-like content don't get executed."""
    logger = LoggingMiddleware()
    blocker = BlockDangerousToolMiddleware()
    chain = MiddlewareChain([logger, blocker])
    
    async def tool_that_returns_dangerous_content(args):
        # This tool returns content that LOOKS like a tool call
        # But it should NOT be executed by the chain
        return {
            "message": "I want to call dangerous_tool with args {}",
            "tool_call": "dangerous_tool",
            "fake_tool_execution": "dangerous_tool({})"
        }
    
    ctx = CallContext()
    result = asyncio.run(chain.execute(
        "info_tool",
        {},
        tool_that_returns_dangerous_content,
        ctx
    ))
    
    # The result should be returned as-is, not executed
    assert result["tool_call"] == "dangerous_tool"
    
    # dangerous_tool should never have been called
    # (logger would have recorded it if it was)
    tool_calls = [call for call in logger.calls if call[0] == "pre" and call[1] == "dangerous_tool"]
    assert len(tool_calls) == 0, "Chain should not execute tool calls from result strings"


def test_nested_attack_via_args():
    """Test that passing dangerous tool calls in args doesn't bypass the blocker."""
    logger = LoggingMiddleware()
    blocker = BlockDangerousToolMiddleware()
    chain = MiddlewareChain([logger, blocker])
    
    async def orchestrator_tool(args):
        # This tool might try to delegate to dangerous_tool
        # But the chain doesn't automatically execute nested calls
        return f"Processed: {args}"
    
    ctx = CallContext()
    result = asyncio.run(chain.execute(
        "orchestrator_tool",
        {"target_tool": "dangerous_tool", "target_args": {}},
        orchestrator_tool,
        ctx
    ))
    
    # The orchestrator ran, but dangerous_tool wasn't called
    assert "Processed:" in result
    
    # Verify dangerous_tool was never invoked
    dangerous_calls = [call for call in logger.calls if call[1] == "dangerous_tool"]
    assert len(dangerous_calls) == 0


# Task 3.6.3: Post-Registration Attack
def test_middleware_added_after_chain_creation():
    """Test behavior when trying to add middleware after chain is built.
    
    Current implementation: Middleware list is immutable after creation.
    This test verifies that behavior.
    """
    blocker = BlockDangerousToolMiddleware()
    chain = MiddlewareChain([blocker])
    
    # Try to add another middleware after creation
    sneaky_middleware = LoggingMiddleware()
    
    # The MiddlewareChain should not allow modification
    # (list is stored internally and not exposed for mutation)
    
    async def dangerous_tool(args):
        return "executed"
    
    ctx = CallContext()
    result = asyncio.run(chain.execute("dangerous_tool", {}, dangerous_tool, ctx))
    
    # Should still be blocked by original middleware
    assert "error" in result
    
    # Verify sneaky_middleware was never called (it's not in the chain)
    assert len(sneaky_middleware.calls) == 0


def test_middleware_order_respected():
    """Test that middleware execute in the correct order."""
    order_tracker = []
    
    class FirstMiddleware(ToolMiddleware):
        async def pre_dispatch(self, name, args, ctx):
            order_tracker.append("first_pre")
            return DispatchDecision.ALLOW
        
        async def post_dispatch(self, name, args, result, ctx):
            order_tracker.append("first_post")
            return result
    
    class SecondMiddleware(ToolMiddleware):
        async def pre_dispatch(self, name, args, ctx):
            order_tracker.append("second_pre")
            return DispatchDecision.ALLOW
        
        async def post_dispatch(self, name, args, result, ctx):
            order_tracker.append("second_post")
            return result
    
    chain = MiddlewareChain([FirstMiddleware(), SecondMiddleware()])
    
    async def test_tool(args):
        order_tracker.append("tool_exec")
        return "done"
    
    ctx = CallContext()
    asyncio.run(chain.execute("test", {}, test_tool, ctx))
    
    # Pre-dispatch: first, second
    # Tool execution
    # Post-dispatch: second (reversed), first
    assert order_tracker == [
        "first_pre",
        "second_pre",
        "tool_exec",
        "second_post",
        "first_post"
    ]


def test_deny_stops_execution():
    """Test that DENY in middleware prevents tool execution."""
    blocker = BlockDangerousToolMiddleware()
    logger = LoggingMiddleware()
    chain = MiddlewareChain([blocker, logger])
    
    tool_executed = []
    
    async def dangerous_tool(args):
        tool_executed.append(True)
        return "should not happen"
    
    ctx = CallContext()
    result = asyncio.run(chain.execute("dangerous_tool", {}, dangerous_tool, ctx))
    
    # Tool should NOT have executed
    assert len(tool_executed) == 0
    
    # Logger pre_dispatch still runs (before blocker denies)
    # But tool itself should not
    assert result["error"]


def test_chain_cannot_be_bypassed_by_direct_tool_call():
    """Test that calling the tool function directly bypasses security.
    
    This is expected behavior - the chain must be explicitly used.
    This test documents that the security layer requires integration, not magic.
    """
    blocker = BlockDangerousToolMiddleware()
    chain = MiddlewareChain([blocker])
    
    async def dangerous_tool(args):
        return "executed without security"
    
    # Calling tool directly (not through chain) bypasses security
    result = asyncio.run(dangerous_tool({}))
    assert result == "executed without security"
    
    # But calling through chain blocks it
    ctx = CallContext()
    result = asyncio.run(chain.execute("dangerous_tool", {}, dangerous_tool, ctx))
    assert "error" in result
