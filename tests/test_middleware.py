import asyncio

from hermes_aegis.middleware.chain import (
    CallContext,
    DispatchDecision,
    MiddlewareChain,
    ToolMiddleware,
)


class AllowMiddleware(ToolMiddleware):
    async def pre_dispatch(self, name, args, ctx):
        ctx.metadata["allow_called"] = True
        return DispatchDecision.ALLOW


class DenyMiddleware(ToolMiddleware):
    async def pre_dispatch(self, name, args, ctx):
        return DispatchDecision.DENY


class UppercasePostMiddleware(ToolMiddleware):
    async def post_dispatch(self, name, args, result, ctx):
        return result.upper()


class TestMiddlewareChain:
    def test_allow_passes_through(self):
        async def handler(args):
            return "result"

        chain = MiddlewareChain([AllowMiddleware()])
        ctx = CallContext()

        result = asyncio.run(chain.execute("tool", {}, handler, ctx))

        assert result == "result"
        assert ctx.metadata.get("allow_called") is True

    def test_deny_blocks(self):
        async def handler(args):
            return "should not reach"

        chain = MiddlewareChain([DenyMiddleware()])
        ctx = CallContext()

        result = asyncio.run(chain.execute("tool", {}, handler, ctx))

        assert "error" in result
        assert "DenyMiddleware" in result["error"]

    def test_post_dispatch_transforms_result(self):
        async def handler(args):
            return "hello"

        chain = MiddlewareChain([UppercasePostMiddleware()])
        ctx = CallContext()

        result = asyncio.run(chain.execute("tool", {}, handler, ctx))

        assert result == "HELLO"

    def test_post_dispatch_runs_reversed(self):
        class AppendA(ToolMiddleware):
            async def post_dispatch(self, name, args, result, ctx):
                return result + "A"

        class AppendB(ToolMiddleware):
            async def post_dispatch(self, name, args, result, ctx):
                return result + "B"

        async def handler(args):
            return ""

        chain = MiddlewareChain([AppendA(), AppendB()])
        ctx = CallContext()

        result = asyncio.run(chain.execute("tool", {}, handler, ctx))

        assert result == "BA"

    def test_deny_stops_chain(self):
        class TrackMiddleware(ToolMiddleware):
            called = False

            async def pre_dispatch(self, name, args, ctx):
                TrackMiddleware.called = True
                return DispatchDecision.ALLOW

        async def handler(args):
            return "x"

        chain = MiddlewareChain([DenyMiddleware(), TrackMiddleware()])
        ctx = CallContext()

        asyncio.run(chain.execute("tool", {}, handler, ctx))

        assert TrackMiddleware.called is False
