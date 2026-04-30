"""Transform registry compatibility layer for Hermes-Aegis plugin hooks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, ClassVar


@dataclass(frozen=True)
class Transform:
    hook_name: str
    name: str
    priority: int
    fn: Callable[..., Any]


class TransformRegistry:
    """Priority-aware registry that installs one dispatcher per hook type."""

    _transforms: ClassVar[dict[str, dict[str, Transform]]] = {}
    _registered_contexts: ClassVar[set[tuple[int, str]]] = set()

    @classmethod
    def reset(cls) -> None:
        cls._transforms = {}
        cls._registered_contexts = set()

    @classmethod
    def register(cls, hook_name: str, name: str, priority: int, fn: Callable[..., Any]) -> None:
        cls._transforms.setdefault(hook_name, {})[name] = Transform(hook_name, name, priority, fn)

    @classmethod
    def _dispatcher(cls, hook_name: str) -> Callable[..., Any]:
        def dispatch(**kwargs: Any) -> Any:
            value = kwargs.get("result", kwargs.get("output", ""))
            for transform in sorted(cls._transforms.get(hook_name, {}).values(), key=lambda item: item.priority):
                call_kwargs = dict(kwargs)
                if hook_name == "transform_terminal_output":
                    call_kwargs["output"] = value
                else:
                    call_kwargs["result"] = value
                value = transform.fn(**call_kwargs)
            return value

        dispatch.__name__ = f"aegis_{hook_name}_dispatcher"
        return dispatch

    @classmethod
    def ensure_hook_registered(cls, hook_name: str, ctx: Any) -> None:
        key = (id(ctx), hook_name)
        if key in cls._registered_contexts:
            return
        ctx.register_hook(hook_name, cls._dispatcher(hook_name))
        cls._registered_contexts.add(key)
