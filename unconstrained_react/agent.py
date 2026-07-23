from shared.llm import ask_gemini
from shared.tools import *


def execute_tool(action, action_input):
    
    if isinstance(action_input, dict):
        action_input = list(action_input.values())[0]
        #because it outputed it as a json not a string
        
    if action == "get_user_history":
        return get_user_history(action_input)

    elif action == "check_ip_reputation":
        return check_ip_reputation(action_input)

    elif action == "block_ip":
        return block_ip(action_input)

    elif action == "send_email":
        return send_email(action_input)

    elif action == "escalate_case":
        return escalate_case(action_input)

    elif action == "close_alert":
        return close_alert(action_input)

    else:
        return "Unknown tool"



def run_agent(alert):

    prompt = """
You are a cybersecurity SOC analyst.

You have these available tools:

- check_ip_reputation(ip)
- get_user_history(user)
- block_ip(ip)
- send_email(user)
- escalate_case(alert)
- close_alert(alert)

Think step by step.

If you need a tool, respond ONLY in this format:

Thought: ...

Action: ...

Action Input: ...

If you are finished, respond ONLY in this format:

Thought: ...

Final Answer: ...

Alert:

{alert}
"""
    #temp
    steps = 0
    while True:
        steps += 1

        if steps > 5:
            print("Stopped: too many steps")
            break
        response = ask_gemini(prompt)

        print("\nLLM Response:")
        print(response)

        if "Final Answer:" in response:
            break

        lines = response.split("\n")

        action = None
        action_input = None

        for line in lines:
            if line.startswith("Action:"):
                action = line.replace("Action:", "").strip()

            if line.startswith("Action Input:"):
                action_input = line.replace("Action Input:", "").strip()


        observation = execute_tool(action, action_input)

        print("\nObservation:")
        print(observation)


        prompt += f"""

    Observation:
    {observation}

    Continue.
    """