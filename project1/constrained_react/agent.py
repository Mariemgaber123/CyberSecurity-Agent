from shared.llm import ask_gemini
from shared.tools import *
from constrained_react.schema import AgentStep


MAX_STEPS = 6

ALLOWED_TOOLS = {
    "check_ip_reputation": check_ip_reputation,
    "get_user_history": get_user_history,
    "block_ip": block_ip,
    "send_email": send_email,
    "escalate_case": escalate_case,
    "close_alert": close_alert
}


def execute_tool(action, value):
    if action in ALLOWED_TOOLS:
        return ALLOWED_TOOLS[action](value)

    return "Tool not allowed"


def run_agent(alert):

    steps = 0

    prompt = f"""
You are a SOC cybersecurity agent.

You have these tools:
{list(ALLOWED_TOOLS.keys())}

Only these actions are allowed:
- check_ip_reputation
- get_user_history
- block_ip
- send_email
- escalate_case
- close_alert
- final_answer

Never invent a new tool.

Do not repeat the same tool unless new information is needed.

You MUST reply only in JSON format:

{{
    "action": "tool_name",
    "input": "value"
}}

If investigation is finished, reply with:

{{
    "action": "final_answer",
    "input": "your conclusion"
}}

Alert:
{alert}
"""

    while steps < MAX_STEPS:

        steps += 1

        response = ask_gemini(prompt)

        print("\nLLM Response:")
        print(response)

        # Validate JSON using Pydantic schema
        try:
            step = AgentStep.model_validate_json(response)

        except Exception as e:
            print("\nInvalid response format")
            print(e)
            break

        # Finish
        if step.action == "final_answer":
            print("\nFINAL ANSWER:")
            print(step.input)
            break

        # Allow-list validation
        if step.action not in ALLOWED_TOOLS:
            print("\nTool not allowed!")
            break

        # Execute tool
        observation = execute_tool(
            step.action,
            step.input
        )

        print("\nObservation:")
        print(observation)

        # Add observation to conversation
        prompt += f"""

Observation:
{observation}

Continue the investigation.

If you have enough information, respond with:

{{
    "action": "final_answer",
    "input": "your conclusion"
}}

Otherwise choose the next tool.
"""

    else:
        print("\nEscalated: Maximum steps reached.")