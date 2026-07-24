test_cases = [

{
    "name": "Clearly Malicious IP",
    "alert": """
IP: 192.168.1.10
User: mariem
Severity: High
Description: Multiple failed login attempts from known malicious IP.
"""
},

{
    "name": "Normal Password Mistake",
    "alert": """
IP: 192.168.1.25
User: jana
Severity: Medium
Description: User entered wrong password three times immediately after changing password.
"""
},

{
    "name": "Suspicious User History",
    "alert": """
IP: 192.168.1.25
User: mariem
Severity: High
Description: Successful login from normal IP, but unusual activity detected.
"""
},

{
    "name": "Unknown Behavior",
    "alert": """
IP: 10.0.0.55
User: maggie
Severity: High
Description: Login at 2:15 AM from an unknown device in another country.
"""
},

{
    "name": "Data Exfiltration",
    "alert": """
IP: 8.8.8.8
User: ali
Severity: Critical
Description: Large amount of confidential files downloaded after successful login.
"""
},
    {
        "name": "Combined Attack (Tricky Input)",
        "alert": """
IP: 192.168.1.10
User: mariem
Severity: High
Description: Known malicious IP, multiple failed login attempts,
login from a new device at midnight, and large data upload to an external server.
"""
    }

]