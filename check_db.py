from mcp_server.db import get_connection


def show_devices():
    conn = get_connection()
    cursor = conn.cursor()

    print("\n=== Devices ===")

    cursor.execute("""
        SELECT ip_address, status
        FROM devices
    """)

    for row in cursor.fetchall():
        print(dict(row))

    conn.close()


def show_audit_logs():
    conn = get_connection()
    cursor = conn.cursor()

    print("\n=== Audit Logs ===")

    cursor.execute("""
        SELECT user_id, action, details
        FROM audit_logs
    """)

    for row in cursor.fetchall():
        print(dict(row))

    conn.close()


if __name__ == "__main__":

    show_devices()
    show_audit_logs()