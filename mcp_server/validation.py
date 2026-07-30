from pydantic import BaseModel, Field, ConfigDict, field_validator
import ipaddress


class UserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user: str = Field(
        min_length=1,
        max_length=100,
        description="Username to investigate"
    )

    @field_validator("user")
    @classmethod
    def validate_user(cls, value):
        value = value.strip()

        if not value:
            raise ValueError("Username cannot be empty.")

        return value


class IPRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str = Field(
        description="IPv4 or IPv6 address"
    )

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value):
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            raise ValueError("Invalid IP address.")


class AlertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert: str = Field(
        min_length=1,
        max_length=300,
        description="Security alert description"
    )

    @field_validator("alert")
    @classmethod
    def validate_alert(cls, value):
        value = value.strip()

        if not value:
            raise ValueError("Alert description cannot be empty.")

        return value