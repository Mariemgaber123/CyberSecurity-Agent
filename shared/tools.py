from mcp_server.db import get_connection
import re

def get_user_history(user):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT user_id, name, role, department
        FROM users
        WHERE name = ?
    """, (user,))

    result = cursor.fetchone()
    conn.close()

    if result is None:
        return {
            "success": False,
            "message": f"User '{user}' not found."
        }

    return {
        "success": True,
        "user": dict(result)
    }





def check_ip_reputation(ip: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT value, reputation, severity
        FROM threat_intelligence
        WHERE value = ?
    """, (ip,))

    result = cursor.fetchone()
    conn.close()

    if result is None:
        return {
            "success": False,
            "message": "IP not found."
        }

    return {
        "success": True,
        "ip": result["value"],
        "reputation": result["reputation"],
        "severity": result["severity"]
    }




def block_ip(ip: str, admin_id: int):

    # -------------------------
    # 1) Validate IP format
    # -------------------------
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"

    if not re.match(pattern, ip):
        return {
            "success": False,
            "message": "Invalid IP address."
        }

    conn = get_connection()
    cursor = conn.cursor()

    # -------------------------
    # 2) Authorization
    # -------------------------
    cursor.execute("""
        SELECT role
        FROM users
        WHERE user_id = ?
    """, (admin_id,))

    user = cursor.fetchone()

    if user is None:
        conn.close()
        return {
            "success": False,
            "message": "User not found."
        }

    if user["role"] != "Security Manager":
        conn.close()
        return {
            "success": False,
            "message": "Not authorized."
        }


    # -------------------------
    # 3) Check that the device exists
    # -------------------------
    cursor.execute("""
        SELECT *
        FROM devices
        WHERE ip_address = ?
    """, (ip,))

    device = cursor.fetchone()

    if device is None:
        conn.close()
        return {
            "success": False,
            "message": "IP address not found."
        }

    # -------------------------
    # 4) Block the device
    # -------------------------
    cursor.execute("""
        UPDATE devices
        SET status = 'Offline'
        WHERE ip_address = ?
    """, (ip,))

    # -------------------------
    # 5) Audit Log
    # -------------------------
    cursor.execute("""
        INSERT INTO audit_logs(user_id, action, details)
        VALUES (?, ?, ?)
    """, (
        admin_id,
        "Block IP",
        f"Blocked IP {ip}"
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": f"{ip} blocked successfully."
    }



def send_email(user: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT user_id
        FROM users
        WHERE name = ?
    """, (user,))

    result = cursor.fetchone()

    if result is None:
        conn.close()
        return {
            "success": False,
            "message": "User not found."
        }

    cursor.execute("""
        INSERT INTO audit_logs(user_id, action, details)
        VALUES (?, ?, ?)
    """, (
        result["user_id"],
        "Send Email",
        f"Email sent to {user}"
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": f"Email sent to {user}"
    }


def close_alert(incident_id: int, admin_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    # Check incident
    cursor.execute(
        "SELECT * FROM incidents WHERE incident_id = ?",
        (incident_id,)
    )
    incident = cursor.fetchone()

    if incident is None:
        conn.close()
        return {
            "success": False,
            "message": "Incident not found."
        }

    # Check admin role
    cursor.execute(
        "SELECT role FROM users WHERE user_id = ?",
        (admin_id,)
    )

    user = cursor.fetchone()

    if user is None:
        conn.close()
        return {
            "success": False,
            "message": "User not found."
        }

    if user["role"] != "Security Manager":
        conn.close()
        return {
            "success": False,
            "message": "Only Security Manager can close incidents."
        }

    cursor.execute("""
        UPDATE incidents
        SET status = 'Closed'
        WHERE incident_id = ?
    """, (incident_id,))

    cursor.execute("""
        INSERT INTO audit_logs(user_id, action, details)
        VALUES (?, ?, ?)
    """, (
        admin_id,
        "Close Incident",
        f"Incident {incident_id} closed."
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "Incident closed successfully."
    }

def escalate_case(incident_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        WHERE incident_id = ?
    """, (incident_id,))

    incident = cursor.fetchone()

    if incident is None:
        conn.close()
        return {
            "success": False,
            "message": "Incident not found."
        }

    cursor.execute("""
        INSERT INTO incident_actions
        (incident_id, user_id, action_type, reason)
        VALUES (?, ?, ?, ?)
    """, (
        incident_id,
        1,
        "Escalate",
        "Escalated by MCP Tool"
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": f"Incident {incident_id} escalated."
    }


def generate_report(days: int):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT incident_id, title, severity, status, created_at
        FROM incidents
        WHERE created_at >= datetime('now', ?)
    """, (f"-{days} days",))

    incidents = cursor.fetchall()


    cursor.execute("""
        SELECT action, details
        FROM audit_logs
    """)

    logs = cursor.fetchall()

    conn.close()

    return {
        "period_days": days,
        "incidents": [dict(row) for row in incidents],
        "actions": [dict(row) for row in logs]
    }