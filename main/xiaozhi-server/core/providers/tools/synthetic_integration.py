"""A side-effect-free tool using a credential resolved by manager-api per call."""

import hmac
import re

from config.manage_api_client import get_synthetic_integration_credential
from plugins_func.register import Action, ActionResponse

from .base import ToolDefinition, ToolExecutor, ToolType

SYNTHETIC_TOOL_NAME = "max_synthetic_integration"


class SyntheticIntegrationExecutor(ToolExecutor):
    def get_tools(self):
        return {SYNTHETIC_TOOL_NAME: ToolDefinition(
            name=SYNTHETIC_TOOL_NAME,
            tool_type=ToolType.SYNTHETIC_INTEGRATION,
            description={"type": "function", "function": {
                "name": SYNTHETIC_TOOL_NAME,
                "description": "Verifica a integração sintética autorizada.",
                "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            }},
        )}

    def has_tool(self, tool_name):
        return tool_name == SYNTHETIC_TOOL_NAME

    async def execute(self, conn, tool_name, arguments):
        if not self.has_tool(tool_name) or arguments != {}:
            return ActionResponse(action=Action.ERROR, response="Chamada sintética inválida.")
        try:
            owner, agent = conn.owner_identity
            credential = await get_synthetic_integration_credential(conn.device_id, owner, agent)
            if not isinstance(credential, str) or not re.fullmatch(r"drill_[a-f0-9]{48}", credential):
                raise ValueError()
            hmac.digest(credential.encode(), b"max:synthetic-integration:v1", "sha256")
        except Exception:
            return ActionResponse(action=Action.ERROR, response="Integração sintética indisponível.")
        return ActionResponse(action=Action.RESPONSE, response="Integração sintética validada.")
