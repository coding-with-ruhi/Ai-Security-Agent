from ollama import chat
from prompts import SYSTEM_PROMPT


def analyze_logs(log_text, summary, failed_attempts, targeted_users, suspicious_ips):

    prompt = f"""
Raw Server Logs:

{log_text}

----------------------------------------

Parsed Summary

Failed Logins:
{summary['failed_logins']}

Successful Logins:
{summary['successful_logins']}

Password Changes:
{summary['password_changes']}

IP Addresses:
{summary['ip_addresses']}

----------------------------------------

Failed Attempts Per IP

{failed_attempts}

----------------------------------------

Targeted Users

{targeted_users}

----------------------------------------

Suspicious IPs

{suspicious_ips}

----------------------------------------

Please generate the security incident report.
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