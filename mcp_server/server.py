import asyncio
from fastmcp import FastMCP
from .capabilities import CAPABILITIES
from .resources import read_resource
from .prompts import get_prompt

mcp = FastMCP("CyberSecurityAgent")

# استيراد ملف الأدوات بعد تعريف mcp
from . import tools
@mcp.resource("policy://critical-device-isolation")
def isolation_policy() -> str:
    return read_resource("policy://critical-device-isolation") or "Policy not found."

@mcp.resource("policy://incident-closure")
def closure_policy() -> str:
    return read_resource("policy://incident-closure") or "Policy not found."

@mcp.prompt("incident_summary")
def prompt_summary(incident_id: str) -> str:
    return get_prompt("incident_summary").format(incident_id=incident_id)

@mcp.prompt("threat_analysis")
def prompt_threat(indicator: str) -> str:
    return get_prompt("threat_analysis").format(indicator=indicator)

@mcp.prompt("closure_report")
def prompt_closure(incident_id: str) -> str:
    return get_prompt("closure_report").format(incident_id=incident_id)

@mcp.tool
def ping() -> str:
    """Check that the MCP server is running."""
    return "MCP Server is running!"

if __name__ == "__main__":
    print("Initializing MCP Server...")
    print("Capabilities:", CAPABILITIES)

    mcp.run(
        transport="sse",
        host="127.0.0.1",
        port=8000
    )