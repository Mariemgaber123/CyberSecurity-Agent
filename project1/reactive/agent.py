from shared.test_cases import test_cases
from shared.tools import *

def run_agent(alert):

    if "malicious" in alert.lower():
        print(check_ip_reputation("192.168.1.10"))
        print(block_ip("192.168.1.10"))
        print(close_alert("Multiple failed login attempts"))

    elif "password change" in alert.lower():
        print(get_user_history("jana"))
        print(send_email("jana"))
        print(close_alert("Password mistake"))

    else:
        print(escalate_case("Unknown behavior"))


for case in test_cases:

    print("=" * 60)
    print(case["name"])
    print("=" * 60)

    run_agent(case["alert"])