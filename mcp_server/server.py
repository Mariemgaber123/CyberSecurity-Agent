from fastmcp import FastMCP

mcp = FastMCP("CyberSecurityAgent")


@mcp.tool
def ping() -> str:
    """
    Check that the MCP server is running.
    """
    return "MCP Server is running!"


from . import tools


if __name__ == "__main__":
    mcp.run()