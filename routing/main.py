from shared.llm import ask_gemini
from shared.test_cases import test_cases
from shared.tools import block_ip, close_alert, escalate_case


ROUTES = ["BLOCK_IP", "CLOSE_ALERT", "ESCALATE"]


def classify_alert(alert):
    prompt = f"""
You are a cybersecurity alert classifier.

Classify the following security alert into exactly ONE category:

BLOCK_IP
Use this when the IP is clearly malicious and should be blocked immediately.

CLOSE_ALERT
Use this when the activity is probably normal or harmless.

ESCALATE
Use this when the alert is dangerous, unclear, or needs human investigation.

Return only the category name.
Do not add explanations or extra text.

Security alert:
{alert}
"""

    result = ask_gemini(prompt).strip().upper()

    if result not in ROUTES:
        return "ESCALATE"

    return result


def get_ip(alert):
    for line in alert.splitlines():
        if line.strip().startswith("IP:"):
            return line.split(":", 1)[1].strip()

    return None


def route_alert(alert):
    category = classify_alert(alert)

    print("Classification:", category)

    if category == "BLOCK_IP":
        ip = get_ip(alert)

        if ip:
            result = block_ip(ip)
            print("Action: Block IP")
            print("Result:", result)
        else:
            result = escalate_case(alert)
            print("Action: Escalate because no IP was found")
            print("Result:", result)

    elif category == "CLOSE_ALERT":
        result = close_alert(alert)
        print("Action: Close alert")
        print("Result:", result)

    else:
        result = escalate_case(alert)
        print("Action: Escalate to security team")
        print("Result:", result)


def main():
    print("=" * 50)
    print("Test Case:", test_cases[-1]["name"])
    print("=" * 50)

    route_alert(test_cases[-1]["alert"])

if _name_ == "__main__":
    main()
