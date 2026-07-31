from fastmcp import FastMCP
from .capabilities import CAPABILITIES
from .resources import list_resources, read_resource
from .prompts import get_prompt
from .resources import list_resources, read_resource


mcp = FastMCP("CyberSecurityAgent")


@mcp.tool
def ping() -> str:
    """
    Check that the MCP server is running.
    """
    return "MCP Server is running!"


from shared import tools

print("Initializing MCP Server...")
print(CAPABILITIES)


if __name__ == "__main__":
    mcp.run()