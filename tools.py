from pathlib import Path
from datetime import datetime
import os


# ==========================================================
# READ SERVER LOG FILE
# ==========================================================

def read_log_file():
    """
    Reads the server log file.
    """

    log_path = Path("logs/server.log")

    if not log_path.exists():
        return "Error: Log file not found."

    with open(log_path, "r", encoding="utf-8") as file:
        logs = file.read()

    return logs


# ==========================================================
# PARSE LOGS
# ==========================================================

def parse_logs(log_text):
    """
    Parse server logs and extract useful information.
    """

    lines = log_text.split("\n")

    failed_logins = 0
    successful_logins = 0
    password_changes = 0
    ip_addresses = []

    for line in lines:

        if "LOGIN FAILED" in line:
            failed_logins += 1

        elif "LOGIN SUCCESS" in line:
            successful_logins += 1

        elif "PASSWORD CHANGED" in line:
            password_changes += 1

        if "ip=" in line:

            ip = line.split("ip=")[1].strip()

            if ip not in ip_addresses:
                ip_addresses.append(ip)

    return {

        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "password_changes": password_changes,
        "ip_addresses": ip_addresses,

    }


# ==========================================================
# FAILED ATTEMPTS PER IP
# ==========================================================

def count_failed_attempts_per_ip(log_text):
    """
    Count failed login attempts for each IP.
    """

    failed_attempts = {}

    for line in log_text.split("\n"):

        if "LOGIN FAILED" in line and "ip=" in line:

            ip = line.split("ip=")[1].strip()

            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    return failed_attempts


# ==========================================================
# TARGETED USERS
# ==========================================================

def find_targeted_users(log_text):
    """
    Count failed login attempts per user.
    """

    targeted_users = {}

    for line in log_text.split("\n"):

        if "LOGIN FAILED" in line and "user=" in line:

            username = line.split("user=")[1].split()[0]

            targeted_users[username] = targeted_users.get(username, 0) + 1

    return targeted_users


# ==========================================================
# SUSPICIOUS IPS
# ==========================================================

def find_suspicious_ips(failed_attempts, threshold=3):
    """
    Identify suspicious IP addresses.
    """

    suspicious_ips = []

    for ip, attempts in failed_attempts.items():

        if attempts >= threshold:
            suspicious_ips.append(ip)

    return suspicious_ips


# ==========================================================
# RISK SCORING ENGINE
# ==========================================================

def calculate_risk_score(
    summary,
    failed_attempts,
    targeted_users,
    suspicious_ips,
):
    """
    Calculate the overall security risk score.
    """

    score = 0

    reasons = []

    # Rule 1
    if summary["failed_logins"] >= 3:

        score += 30

        reasons.append(
            "Multiple failed login attempts detected."
        )

    # Rule 2
    if len(suspicious_ips) > 0:

        score += 25

        reasons.append(
            "Suspicious IP addresses detected."
        )

    # Rule 3
    if "admin" in targeted_users:

        score += 25

        reasons.append(
            "Administrative account targeted."
        )

    # Rule 4
    if summary["password_changes"] > 0:

        score += 20

        reasons.append(
            "Password change detected after suspicious activity."
        )

    return score, reasons


# ==========================================================
# SEVERITY
# ==========================================================

def get_severity(score):
    """
    Convert numerical score into severity.
    """

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    return "LOW"
# ==========================================================
# SECURITY ALERT
# ==========================================================

def show_security_alert(severity, risk_score):
    """
    Display a security alert based on severity.
    """

    print("\n" + "=" * 60)

    if severity == "CRITICAL":

        print("🚨🚨🚨  CRITICAL SECURITY ALERT  🚨🚨🚨")
        print(f"Risk Score : {risk_score}/100")
        print("Immediate investigation is REQUIRED.")

    elif severity == "HIGH":

        print("⚠️ HIGH RISK SECURITY ALERT ⚠️")
        print(f"Risk Score : {risk_score}/100")
        print("Prompt investigation is recommended.")

    elif severity == "MEDIUM":

        print("⚠️ MEDIUM RISK INCIDENT")
        print(f"Risk Score : {risk_score}/100")
        print("Continue monitoring this activity.")

    else:

        print("✅ LOW RISK")
        print(f"Risk Score : {risk_score}/100")
        print("No immediate action required.")

    print("=" * 60)


# ==========================================================
# RECOMMENDED ACTIONS
# ==========================================================

def recommend_actions():
    """
    Display available response actions.
    """

    print("\n========== RECOMMENDED ACTIONS ==========\n")

    print("1. Block Suspicious IP")
    print("2. Force Password Reset")
    print("3. Enable Multi-Factor Authentication")
    print("4. Continue Monitoring")
    print("5. Ignore Incident")


# ==========================================================
# HUMAN IN THE LOOP
# ==========================================================

def get_user_approval():
    """
    Ask the SOC analyst to approve an action.
    """

    while True:

        choice = input("\nSelect an action (1-5): ").strip()

        if choice in ["1", "2", "3", "4", "5"]:
            return choice

        print("\n❌ Invalid option. Please enter a number between 1 and 5.")


# ==========================================================
# EXECUTE ACTION
# ==========================================================

def execute_action(choice, suspicious_ips):
    """
    Simulate execution of security actions.
    """

    print("\n========== ACTION RESULT ==========\n")

    if choice == "1":

        if suspicious_ips:

            print("Blocking suspicious IP address(es)...\n")

            for ip in suspicious_ips:
                print(f"✓ {ip}")

            print("\nFirewall updated successfully.")
            print("(Simulation Only)")

            return "Blocked Suspicious IP(s)"

        else:

            print("No suspicious IP addresses found.")
            return "No IP Blocked"

    elif choice == "2":

        print("Password reset initiated.")
        print("(Simulation Only)")

        return "Forced Password Reset"

    elif choice == "3":

        print("Multi-Factor Authentication enabled.")
        print("(Simulation Only)")

        return "Enabled Multi-Factor Authentication"

    elif choice == "4":

        print("Incident added to monitoring queue.")
        print("(Simulation Only)")

        return "Continue Monitoring"

    elif choice == "5":

        print("Incident ignored.")
        print("(Simulation Only)")

        return "Incident Ignored"

    print("Unknown Action")
    return "Unknown"


# ==========================================================
# SAVE REPORT
# ==========================================================

def save_report(
    analysis,
    risk_score,
    severity,
    action_taken,
):
    """
    Save a complete incident report.
    """

    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now()

    filename = (
        f"reports/security_report_"
        f"{timestamp.strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    )

    report = f"""
============================================================
AI SECURITY INCIDENT REPORT
============================================================

Generated On:
{timestamp.strftime("%Y-%m-%d %H:%M:%S")}

------------------------------------------------------------

Risk Score:
{risk_score}/100

Severity:
{severity}

------------------------------------------------------------

Action Taken:

{action_taken}

============================================================
AI ANALYSIS
============================================================

{analysis}

============================================================
END OF REPORT
============================================================
"""

    with open(filename, "w", encoding="utf-8") as file:

        file.write(report)

    return filename


# ==========================================================
# VIEW REPORTS
# ==========================================================

def view_reports():
    """
    Display all available reports.
    """

    report_folder = "reports"

    os.makedirs(report_folder, exist_ok=True)

    reports = sorted(os.listdir(report_folder))

    if not reports:

        print("\nNo reports available.\n")
        return

    print("\n========== SAVED REPORTS ==========\n")

    for index, report in enumerate(reports, start=1):

        print(f"{index}. {report}")