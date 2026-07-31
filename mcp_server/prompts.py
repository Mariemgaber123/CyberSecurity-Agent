PROMPTS = {
    "incident_summary": """
Summarize Incident {incident_id}
using the available database information.
""",

    "threat_analysis": """
Analyze Threat Indicator:
{indicator}

Explain why it is suspicious.
""",

    "closure_report": """
Write an Incident Closure Report
for Incident {incident_id}.
"""
}

def get_prompt(name):
    return PROMPTS.get(name)