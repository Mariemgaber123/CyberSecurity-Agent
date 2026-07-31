from pydantic import BaseModel, ConfigDict, Field
from fastmcp import Context

from .server import mcp
from .prompts import get_prompt
from .db import get_connection
from .validation import (
    IndicatorLookupRequest,
    UserHistoryRequest,
    IsolateDeviceRequest,
    CloseIncidentRequest,
    EscalateRequest,
)


# ---------------------------------------------------------------------------
# Schema for the elicitation/create response we ask a Security Manager to
# fill in when someone tries to isolate a Critical device (POLICY-IR-001).
# ---------------------------------------------------------------------------
class IsolationApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved: bool = Field(
        description="True to approve isolating this device, False to deny"
    )
    justification: str = Field(
        min_length=1,
        max_length=300,
        description="Why this isolation is approved or denied"
    )


def _log_action(cur, incident_id: int, user_id: int, action_type: str, reason: str):
    cur.execute(
        """
        INSERT INTO incident_actions (incident_id, user_id, action_type, reason)
        VALUES (?, ?, ?, ?)
        """,
        (incident_id, user_id, action_type, reason),
    )


def _audit(cur, user_id: int, action: str, details: str):
    cur.execute(
        "INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)",
        (user_id, action, details),
    )


@mcp.tool
def ping() -> str:
    """Check that the MCP server is running."""
    return "MCP Server is running!"


# ---------------------------------------------------------------------------
# READ-ONLY tools — real queries against threat_intelligence / incident_actions
# ---------------------------------------------------------------------------
@mcp.tool
def ip_reputation(indicator: str) -> str:
    """
    Look up reputation of an indicator of compromise (IP, domain, or hash)
    against known threat_intelligence records for this org's incidents.
    """
    req = IndicatorLookupRequest(indicator=indicator)  # server-side validation

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT value, type, severity, reputation, incident_id
        FROM threat_intelligence
        WHERE value = ?
        """,
        (req.indicator,),
    )
    rows = cur.fetchall()
    conn.close()

    if not rows:
        return f"'{req.indicator}' has no known threat intelligence record. Treat as Unknown."

    lines = [f"Indicator '{req.indicator}' found in {len(rows)} record(s):"]
    for r in rows:
        lines.append(
            f"  - type={r['type']} severity={r['severity']} "
            f"reputation={r['reputation']} (incident #{r['incident_id']})"
        )
    return "\n".join(lines)


@mcp.tool
def user_history(user_id: int) -> str:
    """Get an analyst's incident action history (audit trail of their work)."""
    req = UserHistoryRequest(user_id=user_id)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT name, role FROM users WHERE user_id = ?", (req.user_id,))
    user = cur.fetchone()
    if user is None:
        conn.close()
        return f"No user found with user_id={req.user_id}."

    cur.execute(
        """
        SELECT ia.action_type, ia.reason, ia.created_at, i.title
        FROM incident_actions ia
        JOIN incidents i ON i.incident_id = ia.incident_id
        WHERE ia.user_id = ?
        ORDER BY ia.created_at DESC
        """,
        (req.user_id,),
    )
    actions = cur.fetchall()
    conn.close()

    if not actions:
        return f"{user['name']} ({user['role']}) has no recorded incident actions."

    lines = [f"{user['name']} ({user['role']}) — {len(actions)} recorded action(s):"]
    for a in actions:
        lines.append(f"  - [{a['created_at']}] {a['action_type']} on '{a['title']}': {a['reason']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# WRITE tool #1 — real elicitation, triggered by real device criticality
# ---------------------------------------------------------------------------
@mcp.tool
async def isolate_device(
    incident_id: int,
    device_id: int,
    requested_by: int,
    ctx: Context,
) -> str:
    """
    Isolate a device linked to an incident, cutting its network connection.

    POLICY-IR-001: isolating a device marked "Critical" requires explicit
    human sign-off from a Security Manager before the connection is severed.
    Devices marked "Normal" isolate immediately. This is looked up live
    from the devices table — the model cannot skip the check by claiming
    the device isn't critical.
    """
    req = IsolateDeviceRequest(
        incident_id=incident_id, device_id=device_id, requested_by=requested_by
    )

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT hostname, criticality, status FROM devices WHERE device_id = ?",
        (req.device_id,),
    )
    device = cur.fetchone()

    if device is None:
        conn.close()
        return f"No device found with device_id={req.device_id}."

    if device["status"] == "Isolated":
        conn.close()
        return f"Device '{device['hostname']}' is already isolated."

    # --- Handler-level authorization / elicitation trigger ---
    if device["criticality"] == "Critical":
        try:
            result = await ctx.elicit(
                message=(
                    f"Device '{device['hostname']}' is marked CRITICAL. "
                    f"Isolating it will cut its network connection immediately. "
                    f"Per POLICY-IR-001 this requires Security Manager approval. "
                    f"Approve isolation?"
                ),
                response_type=IsolationApproval,
            )
        except Exception as e:
            conn.close()
            return (
                f"Cannot isolate a Critical device: this client does not "
                f"support elicitation, so Security Manager sign-off cannot "
                f"be collected. ({e})"
            )

        if result.action != "accept" or not result.data.approved:
            reason = result.data.justification if result.action == "accept" else "No response"
            _log_action(cur, req.incident_id, req.requested_by, "Isolate Device",
                        f"DENIED: {reason}")
            _audit(cur, req.requested_by, "Isolation Denied",
                   f"device_id={req.device_id} reason={reason}")
            conn.commit()
            conn.close()
            return f"Isolation of '{device['hostname']}' was NOT approved: {reason}"

        approval_note = f"Approved by manager: {result.data.justification}"
    else:
        approval_note = "Non-critical device, isolated without elicitation."

    cur.execute(
        "UPDATE devices SET status = 'Isolated' WHERE device_id = ?",
        (req.device_id,),
    )
    _log_action(cur, req.incident_id, req.requested_by, "Isolate Device", approval_note)
    _audit(cur, req.requested_by, "Device Isolated",
           f"device_id={req.device_id} hostname={device['hostname']}")

    conn.commit()
    conn.close()

    return f"Device '{device['hostname']}' successfully isolated. ({approval_note})"


# ---------------------------------------------------------------------------
# WRITE tool #2 — real handler-level authorization, no elicitation needed
# because the answer is fully determined by data already in the DB.
# ---------------------------------------------------------------------------
@mcp.tool
def close_incident(incident_id: int, closed_by: int) -> str:
    """
    Close an incident.

    POLICY-IM-002: Critical/High severity incidents can only be closed by
    a user holding the 'Security Manager' role. This is checked against
    live data (incidents.severity, users.role) in the handler — a client
    cannot bypass it by simply asserting authorization in the arguments.
    """
    req = CloseIncidentRequest(incident_id=incident_id, closed_by=closed_by)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT title, severity, status FROM incidents WHERE incident_id = ?",
        (req.incident_id,),
    )
    incident = cur.fetchone()
    if incident is None:
        conn.close()
        return f"No incident found with incident_id={req.incident_id}."

    if incident["status"] == "Closed":
        conn.close()
        return f"Incident '{incident['title']}' is already closed."

    cur.execute("SELECT name, role FROM users WHERE user_id = ?", (req.closed_by,))
    user = cur.fetchone()
    if user is None:
        conn.close()
        return f"No user found with user_id={req.closed_by}."

    # --- Handler-level authorization check ---
    if incident["severity"] in ("Critical", "High") and user["role"] != "Security Manager":
        _audit(cur, req.closed_by, "Closure Denied",
               f"incident_id={req.incident_id} role={user['role']} severity={incident['severity']}")
        conn.commit()
        conn.close()
        return (
            f"Authorization denied: incident '{incident['title']}' is "
            f"{incident['severity']} severity and can only be closed by a "
            f"Security Manager (POLICY-IM-002). {user['name']} is a {user['role']}."
        )

    cur.execute(
        "UPDATE incidents SET status = 'Closed' WHERE incident_id = ?",
        (req.incident_id,),
    )
    _log_action(cur, req.incident_id, req.closed_by, "Close Incident",
                f"Closed by {user['name']} ({user['role']})")
    _audit(cur, req.closed_by, "Incident Closed",
           f"incident_id={req.incident_id} title={incident['title']}")

    conn.commit()
    conn.close()

    return f"Incident '{incident['title']}' closed by {user['name']} ({user['role']})."


@mcp.tool
def escalate(incident_id: int, escalated_by: int, reason: str) -> str:
    """Escalate an incident, moving it into active investigation."""
    req = EscalateRequest(incident_id=incident_id, escalated_by=escalated_by, reason=reason)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT title, status FROM incidents WHERE incident_id = ?", (req.incident_id,))
    incident = cur.fetchone()
    if incident is None:
        conn.close()
        return f"No incident found with incident_id={req.incident_id}."

    cur.execute(
        "UPDATE incidents SET status = 'Investigating' WHERE incident_id = ?",
        (req.incident_id,),
    )
    _log_action(cur, req.incident_id, req.escalated_by, "Escalate", req.reason)
    _audit(cur, req.escalated_by, "Incident Escalated",
           f"incident_id={req.incident_id} reason={req.reason}")

    conn.commit()
    conn.close()

    return f"Incident '{incident['title']}' escalated: {req.reason}"


@mcp.tool
def notify_user(user_id: int) -> str:
    """Send a security notification to a user (not modeled in DB — stub)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT name FROM users WHERE user_id = ?", (user_id,))
    user = cur.fetchone()
    conn.close()

    if user is None:
        return f"No user found with user_id={user_id}."
    return f"Notification sent to {user['name']}."


# ---------------------------------------------------------------------------
# SAMPLING — the client's LLM writes the closure report, using real
# incident context pulled from the DB (not a hardcoded string).
# ---------------------------------------------------------------------------
@mcp.tool
async def generate_closure_report(incident_id: int, ctx: Context) -> str:
    """
    Generate a written incident closure report using the client's LLM
    (MCP sampling), grounded in the real incident record.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT title, description, severity, status FROM incidents WHERE incident_id = ?",
        (incident_id,),
    )
    incident = cur.fetchone()

    cur.execute(
        """
        SELECT action_type, reason, created_at FROM incident_actions
        WHERE incident_id = ? ORDER BY created_at
        """,
        (incident_id,),
    )
    actions = cur.fetchall()
    conn.close()

    if incident is None:
        return f"No incident found with incident_id={incident_id}."

    action_log = "\n".join(
        f"- {a['action_type']} at {a['created_at']}: {a['reason']}" for a in actions
    ) or "No actions recorded."

    prompt_text = get_prompt("closure_report").format(incident_id=incident_id) + f"""

Incident title: {incident['title']}
Severity: {incident['severity']}
Status: {incident['status']}
Description: {incident['description']}

Action log:
{action_log}
"""

    result = await ctx.sample(
        messages=prompt_text,
        system_prompt=(
            "You are a SOC analyst. Write a concise, professional incident "
            "closure report in 3-5 sentences, suitable for an audit log, "
            "based only on the incident data given."
        ),
        max_tokens=400,
    )

    return result.text