import asyncio
import traceback

from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.types import (
    CreateMessageRequestParams,
    CreateMessageResult,
    TextContent,
    ElicitRequestParams,
    ElicitResult,
)

SERVER_URL = "http://127.0.0.1:8000/sse"

# ---------------------------------------------------------------------------
# SAMPLING CALLBACK — client's LLM answers server sampling/createMessage
# requests. Requires: pip install anthropic ; export ANTHROPIC_API_KEY=...
# ---------------------------------------------------------------------------
try:
    from anthropic import Anthropic
    _anthropic_client = Anthropic()
    _HAVE_ANTHROPIC = True
except Exception:
    _anthropic_client = None
    _HAVE_ANTHROPIC = False


async def sampling_callback(context, params: CreateMessageRequestParams) -> CreateMessageResult:
    print("\n[SAMPLING REQUEST RECEIVED FROM SERVER]")

    messages = []
    for m in params.messages:
        content = m.content
        text = content.text if hasattr(content, "text") else str(content)
        messages.append({"role": m.role, "content": text})

    if not _HAVE_ANTHROPIC:
        fallback_text = (
            "[LOCAL FALLBACK - no ANTHROPIC_API_KEY set] "
            "Incident closure report would be generated here."
        )
        print(f"[SAMPLING RESPONSE] {fallback_text}")
        return CreateMessageResult(
            role="assistant",
            content=TextContent(type="text", text=fallback_text),
            model="fallback-local",
            stopReason="endTurn",
        )

    response = _anthropic_client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=params.maxTokens or 400,
        system=params.systemPrompt or "",
        messages=messages,
    )

    text = response.content[0].text
    print(f"[SAMPLING RESPONSE] {text[:200]}...")

    return CreateMessageResult(
        role="assistant",
        content=TextContent(type="text", text=text),
        model="claude-sonnet-4-6",
        stopReason="endTurn",
    )


# ---------------------------------------------------------------------------
# ELICITATION CALLBACK — client side of elicitation/create. This is what
# fires when isolate_device() hits a Critical device on the server. In a
# real client this would show a UI prompt to a Security Manager; here it
# prompts on the console to keep the demo runnable end-to-end.
# ---------------------------------------------------------------------------
async def elicitation_callback(context, params: ElicitRequestParams) -> ElicitResult:
    print("\n[ELICITATION REQUEST FROM SERVER]")
    print(params.message)

    answer = input("Approve this action? (yes/no): ").strip().lower()
    approved = answer in ("yes", "y")
    justification = input("Justification: ").strip() or "No justification provided"

    return ElicitResult(
        action="accept",
        content={"approved": approved, "justification": justification},
    )


async def main():
    print(f"Connecting to {SERVER_URL}")

    try:
        async with sse_client(SERVER_URL) as streams:
            # Passing both callbacks here is the client DECLARING sampling +
            # elicitation support during the initialize handshake. Omit
            # either one and the matching server-side call (ctx.sample /
            # ctx.elicit) will fail — that's the "client without a
            # capability" case the assignment wants handled gracefully
            # (see isolate_device's try/except around ctx.elicit).
            async with ClientSession(
                streams[0],
                streams[1],
                sampling_callback=sampling_callback,
                elicitation_callback=elicitation_callback,
            ) as session:

                print("\n========== INITIALIZE ==========")

                init = await session.initialize()

                print("Connected Successfully")
                print("Server:", init.serverInfo.name)
                print("Version:", init.serverInfo.version)
                print("Server capabilities:", init.capabilities)

                server_has_prompts = bool(getattr(init.capabilities, "prompts", None))
                server_has_resources = bool(getattr(init.capabilities, "resources", None))

                print("\n========== TOOLS ==========")
                tools = await session.list_tools()
                for tool in tools.tools:
                    print(f"- {tool.name}: {tool.description}")

                print("\n========== RESOURCES ==========")
                if server_has_resources:
                    resources = await session.list_resources()
                    for r in resources.resources:
                        print(f"- {r.uri}")
                    resource = await session.read_resource("policy://critical-device-isolation")
                    print(resource.contents[0].text)
                else:
                    print("Server did not declare resources capability, skipping.")

                print("\n========== PROMPTS ==========")
                if server_has_prompts:
                    prompts = await session.list_prompts()
                    for p in prompts.prompts:
                        print("-", p.name)
                else:
                    print("Server did not declare prompts capability, skipping.")

                print("\n========== ping ==========")
                result = await session.call_tool("ping", arguments={})
                print(result.content[0].text)

                print("\n========== ip_reputation (known malicious IP) ==========")
                result = await session.call_tool(
                    "ip_reputation", arguments={"indicator": "192.168.1.50"}
                )
                print(result.content[0].text)

                print("\n========== user_history (Mariem, user_id=1) ==========")
                result = await session.call_tool("user_history", arguments={"user_id": 1})
                print(result.content[0].text)

                print("\n========== isolate_device: NORMAL device (no elicitation) ==========")
                result = await session.call_tool(
                    "isolate_device",
                    arguments={"incident_id": 2, "device_id": 2, "requested_by": 3},
                )
                print(result.content[0].text)

                print("\n========== isolate_device: CRITICAL device (triggers elicitation) ==========")
                print("You will be prompted on THIS console as the Security Manager.")
                result = await session.call_tool(
                    "isolate_device",
                    arguments={"incident_id": 1, "device_id": 1, "requested_by": 2},
                )
                print(result.content[0].text)

                print("\n========== close_incident: UNAUTHORIZED (Junior Analyst, High severity) ==========")
                result = await session.call_tool(
                    "close_incident", arguments={"incident_id": 1, "closed_by": 3}
                )
                print(result.content[0].text)

                print("\n========== close_incident: AUTHORIZED (Security Manager) ==========")
                result = await session.call_tool(
                    "close_incident", arguments={"incident_id": 1, "closed_by": 2}
                )
                print(result.content[0].text)

                print("\n========== escalate ==========")
                result = await session.call_tool(
                    "escalate",
                    arguments={
                        "incident_id": 2,
                        "escalated_by": 1,
                        "reason": "Ransomware indicators confirmed, needs tier-2 review",
                    },
                )
                print(result.content[0].text)

                print("\n========== SAMPLING: generate_closure_report ==========")
                print("This triggers sampling/createMessage, answered by THIS "
                      "client's model via sampling_callback().")
                result = await session.call_tool(
                    "generate_closure_report", arguments={"incident_id": 1}
                )
                print(result.content[0].text)

                print("\n========== FINISHED ==========")

    except Exception:
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())