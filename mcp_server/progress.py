import asyncio
from fastmcp import Context


async def show_progress(task_name: str, ctx: Context):
    """
    Report progress updates to the MCP client.
    """

    for i in range(0, 101, 20):
        await ctx.report_progress(
            progress=i,
            total=100
        )

        print(f"[PROGRESS] {task_name}: {i}%")

        await asyncio.sleep(0.5)

    print(f"[DONE] {task_name}")