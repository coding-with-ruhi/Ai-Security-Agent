from ollama import chat
from prompts import SYSTEM_PROMPT


# ==========================================================
# AI SECURITY ANALYSIS
# ==========================================================

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
    """
    Send structured security information to the local Llama model
    and return a professional incident report.
    """

    user_prompt = f"""
You have been provided with a security incident.

==============================
RAW SERVER LOGS
==============================

{log_text}

==============================
LOG SUMMARY
==============================

Failed Logins:
{summary['failed_logins']}

Successful Logins:
{summary['successful_logins']}

Password Changes:
{summary['password_changes']}

IP Addresses:
{", ".join(summary['ip_addresses'])}

==============================
FAILED ATTEMPTS PER IP
==============================

{failed_attempts}

==============================
TARGETED USERS
==============================

{targeted_users}

==============================
SUSPICIOUS IPS
==============================

{suspicious_ips}

==============================
RISK ASSESSMENT
==============================

Risk Score:
{risk_score}/100

Severity:
{severity}

Reasons:

{chr(10).join("- " + reason for reason in reasons)}

==============================
TASK
==============================

Generate a professional cybersecurity incident report.

Your report must include:

1. Executive Summary

2. Threats Detected

3. Risk Assessment

4. Affected Users

5. Suspicious IP Addresses

6. Possible Attack Type

7. Recommendations

8. Incident Response Plan

Do not invent information.

Only use the supplied logs and security data.
"""

    try:

        response = chat(

            model="llama3.2:3b",

            messages=[

                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },

                {
                    "role": "user",
                    "content": user_prompt,
                },

            ],

        )

        return response["message"]["content"]

    except Exception as error:

        return f"""
============================================================

AI ERROR

Unable to generate the security report.

Reason:

{error}

Please verify:

1. Ollama is running.

2. llama3.2:3b is installed.

3. Internet is NOT required.

4. Ollama service is active.

============================================================
"""