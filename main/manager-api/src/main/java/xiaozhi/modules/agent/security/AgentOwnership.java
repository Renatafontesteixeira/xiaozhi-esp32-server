package xiaozhi.modules.agent.security;

import xiaozhi.common.exception.ErrorCode;
import xiaozhi.common.exception.RenException;
import xiaozhi.modules.agent.entity.AgentEntity;
import xiaozhi.modules.device.entity.DeviceEntity;

/** Personal resource ownership never inherits the technical superadmin bypass. */
public final class AgentOwnership {
    private AgentOwnership() { }

    public static void requireOwner(AgentEntity agent, Long owner) {
        if (agent == null || owner == null || !owner.equals(agent.getUserId())) {
            throw new RenException(ErrorCode.NO_PERMISSION);
        }
    }

    public static void requireConsistent(DeviceEntity device, AgentEntity agent) {
        if (device == null || agent == null || agent.getId() == null
                || !agent.getId().equals(device.getAgentId())) {
            throw new RenException(ErrorCode.NO_PERMISSION);
        }
        requireOwner(agent, device.getUserId());
    }
}
