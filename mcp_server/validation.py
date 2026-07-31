from pydantic import BaseModel, Field, ConfigDict, field_validator


# ---------------------------------------------------------------------------
# NOTE: these models are the JSON-Schema layer (types, required fields,
# additionalProperties=forbid). They are NOT the same thing as the
# handler-level checks in tools.py (e.g. "is this user actually a Security
# Manager", "is this device actually Critical"). Both layers are required
# by the assignment — a valid-shaped request can still be an unauthorized
# request, and only the handler can know that, because it has to look at
# live data in security.db, not just the shape of the arguments.
# ---------------------------------------------------------------------------


class IndicatorLookupRequest(BaseModel):
    """Look up an IOC (IP / Domain / Hash) in threat_intelligence."""
    model_config = ConfigDict(extra="forbid")

    indicator: str = Field(
        min_length=1,
        max_length=253,
        description="The IP address, domain, or file hash to look up"
    )

    @field_validator("indicator")
    @classmethod
    def not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Indicator cannot be empty.")
        return value


class UserHistoryRequest(BaseModel):
    """Look up a user's incident action history."""
    model_config = ConfigDict(extra="forbid")

    user_id: int = Field(ge=1, description="users.user_id to look up")


class IsolateDeviceRequest(BaseModel):
    """
    Isolate a device that is part of an incident.
    Isolating a Critical device requires Security Manager sign-off
    (POLICY-IR-001) — enforced in the handler, not here.
    """
    model_config = ConfigDict(extra="forbid")

    incident_id: int = Field(ge=1, description="incidents.incident_id this isolation relates to")
    device_id: int = Field(ge=1, description="devices.device_id to isolate")
    requested_by: int = Field(ge=1, description="users.user_id making the request")


class CloseIncidentRequest(BaseModel):
    """
    Close an incident.
    Critical/High severity incidents can only be closed by a Security
    Manager (POLICY-IM-002) — enforced in the handler, not here.
    """
    model_config = ConfigDict(extra="forbid")

    incident_id: int = Field(ge=1, description="incidents.incident_id to close")
    closed_by: int = Field(ge=1, description="users.user_id performing the closure")


class EscalateRequest(BaseModel):
    """Escalate an incident to tier-2 / a Security Manager."""
    model_config = ConfigDict(extra="forbid")

    incident_id: int = Field(ge=1, description="incidents.incident_id to escalate")
    escalated_by: int = Field(ge=1, description="users.user_id performing the escalation")
    reason: str = Field(
        min_length=1,
        max_length=300,
        description="Why this incident is being escalated"
    )

    @field_validator("reason")
    @classmethod
    def not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Reason cannot be empty.")
        return value