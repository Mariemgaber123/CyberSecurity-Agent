from shared.tools import (
    get_user_history,
    check_ip_reputation,
    block_ip,
    send_email,
    escalate_case,
    close_alert,
)

from .server import mcp
from .validation import UserRequest, IPRequest, AlertRequest
from .progress import show_progress
from .elicitation import confirm_action


# =========================
# READ TOOLS
# =========================

@mcp.tool
def user_history(user: str):
    request = UserRequest(user=user)

    show_progress("Getting user history")

    return get_user_history(request.user)


@mcp.tool
def ip_reputation(ip: str):
    request = IPRequest(ip=ip)

    show_progress("Checking IP reputation")

    return check_ip_reputation(request.ip)


# =========================
# WRITE TOOLS
# =========================

@mcp.tool
def block(ip: str, role: str):
    request = IPRequest(ip=ip)

    # Handler Authorization
    if role.lower() != "admin":
        return "Unauthorized. Only admins can block IPs."

    if not confirm_action(f"block IP {request.ip}"):
        return "Operation cancelled."

    show_progress("Blocking IP")

    return block_ip(request.ip)


@mcp.tool
def notify_user(user: str):
    request = UserRequest(user=user)

    show_progress("Sending email")

    return send_email(request.user)


@mcp.tool
def escalate(alert: str):
    request = AlertRequest(alert=alert)

    show_progress("Escalating case")

    return escalate_case(request.alert)


@mcp.tool
def close(alert: str, role: str):
    request = AlertRequest(alert=alert)

    # Handler Authorization
    if role.lower() != "admin":
        return "Unauthorized. Only admins can close alerts."

    if not confirm_action(f"close alert '{request.alert}'"):
        return "Operation cancelled."

    show_progress("Closing alert")

    return close_alert(request.alert)