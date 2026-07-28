def get_user_history(user):
    return f"User {user} has 5 failed login attempts in the last hour."

def check_ip_reputation(ip):
    return f"IP {ip} reputation: malicious."

def block_ip(ip):
    return f"{ip} has been blocked."

def send_email(user):
    return f"Email sent to {user}."

def escalate_case(alert):
    return "Case escalated."

def close_alert(alert):
    return "Alert closed."