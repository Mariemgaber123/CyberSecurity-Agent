test_cases = [

    {
        "name": "Malicious IP",
        "alert": """
IP: 192.168.1.10
User: mariem
Severity: High
Description: Multiple failed login attempts from known malicious IP.
"""
    },


    {
        "name": "Normal User Mistake",
        "alert": """
IP: 192.168.1.25
User: ahmed
Severity: Medium
Description: 3 failed login attempts after password change.
"""
    },


    {
        "name": "Unknown Behavior",
        "alert": """
IP: 10.0.0.55
User: sara
Severity: High
Description: Unusual login activity detected at midnight with unknown device.
"""
    }

]