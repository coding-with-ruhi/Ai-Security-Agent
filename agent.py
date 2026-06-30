from ollama import chat
from prompts import SYSTEM_PROMPT


def analyze_logs(
    log_text,
    summary,
    failed_attempts,
    targeted_users,
    suspicious_ips,
    risk_score,
    severity,
    reasons,
):

    prompt = f"""
{SYSTEM_PROMPT}

==================================================

RAW SERVER LOGS

{log_text}

==================================================

PARSED SUMMARY

Failed Logins:
{summary['failed_logins']}

Successful Logins:
{summary['successful_logins']}

Password Changes:
{summary['password_changes']}

IP Addresses:
{summary['ip_addresses']}

==================================================

FAILED ATTEMPTS PER IP

{failed_attempts}

==================================================

TARGETED USERS

{targeted_users}

==================================================

SUSPICIOUS IPS

{suspicious_ips}

==================================================

RISK ASSESSMENT

Risk Score:
{risk_score}/100

Severity:
{severity}

Reasons:
{chr(10).join(reasons)}

==================================================

Please generate the complete security incident report.
"""

    response = chat(
        model="llama3.2:3b",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response.message.content