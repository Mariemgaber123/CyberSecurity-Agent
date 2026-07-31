from pydantic import BaseModel
from typing import Literal


class AgentStep(BaseModel):

    action: Literal[
        "check_ip_reputation",
        "get_user_history",
        "block_ip",
        "send_email",
        "escalate_case",
        "close_alert",
        "final_answer"
    ]

    input: str