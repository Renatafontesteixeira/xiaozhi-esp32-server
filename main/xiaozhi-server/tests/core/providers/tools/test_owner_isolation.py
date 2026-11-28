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


def test_synthetic_dispatch_resolves_fresh_credential_for_the_bound_device(monkeypatch):
    import hmac
    import json
    import httpx
    from unittest.mock import Mock
    from config.manage_api_client import ManageApiClient
    from core.providers.tools.synthetic_integration import SYNTHETIC_TOOL_NAME

    session = {"deviceId": "02:00:00:00:01:01", "ownerId": "11", "agentId": "agent-a"}
    conn = SimpleNamespace(config={"read_config_from_api": True}, device_id=session["deviceId"])
    apply_server_identity(conn, {
        "identity": {"ownerId": "11", "agentId": "agent-a"},
        "personal_tools_allowed": False,
        "synthetic_tool_allowed": True,
    })
    monkeypatch.setattr("core.providers.tools.unified_tool_manager.setup_logging", Mock())
    manager = ToolManager(conn)
    other_executor = Mock()
    manager.register_executor(ToolType.SERVER_PLUGIN, other_executor)

    key = None
    requests = []

    def backend(request):
        assert request.url.path == "/xiaozhi/config/max-synthetic-credential"
        binding = json.loads(request.content)
        requests.append(binding)
        return httpx.Response(200, json={"code": 0, "data": key} if binding == session and key else {"code": 10169})

    async def send(client, request, **kwargs):
        response = backend(request)
        response.request = request
        return response

    monkeypatch.setattr(httpx.AsyncClient, "send", send)
    monkeypatch.setattr(ManageApiClient, "_instance", None)
    digest = Mock(wraps=hmac.digest)
    monkeypatch.setattr("core.providers.tools.synthetic_integration.hmac.digest", digest)
    ManageApiClient({"manager-api": {"url": "http://fixture.invalid/xiaozhi", "secret": "fixture"}})

    assert manager.get_supported_tool_names() == [SYNTHETIC_TOOL_NAME]
    assert [item["function"]["name"] for item in manager.get_function_descriptions()] == [SYNTHETIC_TOOL_NAME]
    assert asyncio.run(manager.execute_tool("external_tool", {})).action == Action.ERROR
    assert asyncio.run(manager.execute_tool(SYNTHETIC_TOOL_NAME, {"ownerId": "22"})).action == Action.ERROR
    assert requests == []
    assert asyncio.run(manager.execute_tool(SYNTHETIC_TOOL_NAME, {})).action == Action.ERROR
    key = "drill_" + "a" * 48
    result = asyncio.run(manager.execute_tool(SYNTHETIC_TOOL_NAME, {}))
    assert result.action == Action.RESPONSE and key not in result.response
    conn.device_id = "02:00:00:00:02:01"
    assert asyncio.run(manager.execute_tool(SYNTHETIC_TOOL_NAME, {})).action == Action.ERROR
    conn.device_id = session["deviceId"]
    key = None
    assert asyncio.run(manager.execute_tool(SYNTHETIC_TOOL_NAME, {})).action == Action.ERROR
    assert len(requests) == 4
    digest.assert_called_once_with(("drill_" + "a" * 48).encode(), b"max:synthetic-integration:v1", "sha256")
    assert not other_executor.mock_calls

    with pytest.raises(ValueError):
        apply_server_identity(conn, {"synthetic_tool_allowed": True})
    assert manager.get_supported_tool_names() == []
