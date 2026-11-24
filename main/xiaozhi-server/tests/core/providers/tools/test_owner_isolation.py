import asyncio
from types import SimpleNamespace
import pytest
from core.utils.owner_identity import apply_server_identity, tools_allowed
from core.providers.tools.unified_tool_manager import ToolManager
from core.providers.tools.base import ToolType, ToolDefinition
from plugins_func.register import Action, ActionResponse


def test_stable_identity_is_server_supplied_and_failed_refresh_revokes_authority():
    first = SimpleNamespace(config={"read_config_from_api": True})
    second = SimpleNamespace(config={"read_config_from_api": True})
    config = {"identity": {"ownerId": "11", "agentId": "agent-a"}, "personal_tools_allowed": False}
    apply_server_identity(first, config)
    apply_server_identity(second, config)
    assert first.owner_identity == second.owner_identity == ("11", "agent-a")
    assert not tools_allowed(first)
    apply_server_identity(first, dict(config, personal_tools_allowed=True))
    assert tools_allowed(first)
    with pytest.raises(ValueError):
        apply_server_identity(first, {"ownerId": "11", "agentId": "agent-b", "personal_tools_allowed": True})
    assert first.owner_identity is None and not tools_allowed(first)


def test_tool_manager_denies_plugins_mcp_iot_even_if_advertised_or_called_directly():
    conn = SimpleNamespace(config={"read_config_from_api": True})
    apply_server_identity(conn, {"identity": {"ownerId": "22", "agentId": "agent-b"}})
    manager = ToolManager(conn)
    calls = []

    class Executor:
        def get_tools(self):
            calls.append("catalog")
            return {}

        async def execute(self, *args):
            calls.append("effect")
            return ActionResponse(action=Action.RESPONSE, response="executed")

    for kind in ToolType:
        manager.register_executor(kind, Executor())
    # A stale catalog must never restore permission.
    manager._cached_tools = {"other_owner_tool": SimpleNamespace(tool_type=next(iter(ToolType)))}
    manager._cached_function_descriptions = [{"name": "other_owner_tool"}]
    assert manager.get_all_tools() == {}
    assert manager.get_function_descriptions() == []
    result = asyncio.run(manager.execute_tool("other_owner_tool", {"ownerId": "11", "agentId": "agent-a"}))
    assert result.action == Action.ERROR
    assert calls == []


def test_standalone_native_mode_preserves_existing_tools():
    assert tools_allowed(SimpleNamespace(config={}))
