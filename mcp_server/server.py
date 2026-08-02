
from fastmcp import FastMCP, Context
from pydantic import BaseModel, Field #Validation

class BlockIPRequest(BaseModel):

    ip: str = Field(
        pattern=r"^(\d{1,3}\.){3}\d{1,3}$"
    )

    admin_id: int = Field(
        gt=0
    )

from shared.tools import (
    get_user_history,
    check_ip_reputation,
    block_ip,
    send_email,
    escalate_case,
    close_alert,
    generate_report,
)

mcp = FastMCP("CyberSecurity Server")

@mcp.tool
def user_history(user: str):
    return get_user_history(user)


@mcp.tool
def ip_reputation(ip: str):
    return check_ip_reputation(ip)


@mcp.tool
def block(request: BlockIPRequest):

    return block_ip(
        request.ip,
        request.admin_id
    )

@mcp.tool
def close(incident_id: int, admin_id: int):
    return close_alert(incident_id, admin_id)


@mcp.tool
def escalate(incident_id: int):
    return escalate_case(incident_id)


@mcp.tool
def email(user: str):
    return send_email(user)

@mcp.tool
async def security_report(days: int, ctx: Context):

    data = generate_report(days)

    prompt = f"""
    You are a SOC analyst.

    Generate a security report for the last {days} days.

    Data:
    {data}

    Include:
    - Summary
    - Detected threats
    - Severity analysis
    - Recommendations
    """

    try:
        result = await ctx.sample(prompt)

        return {
            "success": True,
            "report": result.text
        }

    except Exception as e:
        return {
            "success": True,
            "report": data,
            "message": "LLM sampling unavailable"
        }

    
if __name__ == "__main__":
    mcp.run()