"""Only manager-api supplies identity and execution authority, never client headers."""


def apply_server_identity(conn, config):
    conn.owner_identity = None
    conn.personal_tools_allowed = False
    identity = config.get("identity")
    if (not isinstance(identity, dict)
            or not isinstance(identity.get("ownerId"), str)
            or not identity["ownerId"].isdigit()
            or not isinstance(identity.get("agentId"), str)
            or not identity["agentId"]):
        raise ValueError("Authorized agent identity required")
    conn.owner_identity = (identity["ownerId"], identity["agentId"])
    conn.personal_tools_allowed = config.get("personal_tools_allowed") is True


def tools_allowed(conn):
    # Offline/native single-user mode retains its existing behavior.
    return (not conn.config.get("read_config_from_api", False)
            or (getattr(conn, "owner_identity", None) is not None
                and getattr(conn, "personal_tools_allowed", False) is True))
