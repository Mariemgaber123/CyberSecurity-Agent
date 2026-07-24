from shared.llm import ask_gemini
from shared.tools import *


def malicious_ip_workflow(ip, user):
    print(check_ip_reputation(ip))
    print(block_ip(ip))
    print(send_email(user))
    print(close_alert("Multiple failed login attempts"))


def normal_user_workflow(user):
    print(get_user_history(user))
    print(close_alert("Password mistake"))


def unknown_behavior_workflow(alert):
    print(escalate_case(alert))


def run_agent(alert):

    prompt = f"""
You are a SOC classifier.

Classify this alert into ONLY one category.

Categories:
- MALICIOUS_IP
- NORMAL_USER_MISTAKE
- UNKNOWN_BEHAVIOR

Reply ONLY with the category name.

Alert:
{alert}
"""

    category = ask_gemini(prompt).strip()

    print("Category:", category)

    # Extract IP and User from the alert
    ip = ""
    user = ""

    for line in alert.split("\n"):

        line = line.strip()

        if line.startswith("IP:"):
            ip = line.replace("IP:", "").strip()

        elif line.startswith("User:"):
            user = line.replace("User:", "").strip()

    # Route to the correct workflow
    if category == "MALICIOUS_IP":
        malicious_ip_workflow(ip, user)

    elif category == "NORMAL_USER_MISTAKE":
        normal_user_workflow(user)

    elif category == "UNKNOWN_BEHAVIOR":
        unknown_behavior_workflow(alert)

    else:
        print("Unknown category")