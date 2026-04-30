from hooks.transforms import aegis_secret_scan, register_transforms


def test_redacts_anthropic_api_key():
    result = aegis_secret_scan(result="key=sk-ant-api03-abc123def456ghi789jkl012mno345")
    assert "sk-ant-" not in result
    assert "[AEGIS:REDACTED" in result


def test_redacts_aws_access_key():
    result = aegis_secret_scan(result="AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in result


def test_redacts_github_pat():
    result = aegis_secret_scan(result="token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    assert "ghp_" not in result


def test_clean_output_unchanged():
    original = "build successful, 42 tests passed"
    assert aegis_secret_scan(result=original) == original


def test_register_transforms_registers_single_hook_per_type():
    from aegis_core.transforms import TransformRegistry

    TransformRegistry.reset()

    class FakeCtx:
        def __init__(self):
            self.hooks = []

        def register_hook(self, name, fn):
            self.hooks.append((name, fn))

    ctx = FakeCtx()
    register_transforms(ctx)
    register_transforms(ctx)

    assert [name for name, _fn in ctx.hooks] == ["transform_tool_result", "transform_terminal_output"]
    TransformRegistry.reset()
