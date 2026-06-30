from pathlib import Path
from datetime import datetime
import os

def read_log_file():
    """
    Reads the server log file and returns its contents.
    """

    log_path = Path("logs/server.log")

    if not log_path.exists():
        return "Error: Log file not found."

    with open(log_path, "r", encoding="utf-8") as file:
        data = file.read()

    return data
def parse_logs(log_text):
    """
    Extract useful information from the log file.
    """

    lines = log_text.split("\n")

    failed_logins = 0
    successful_logins = 0
    password_changes = 0
    ip_addresses = []

    for line in lines:

        if "LOGIN FAILED" in line:
            failed_logins += 1

        if "LOGIN SUCCESS" in line:
            successful_logins += 1

        if "PASSWORD CHANGED" in line:
            password_changes += 1

        if "ip=" in line:
            ip = line.split("ip=")[1].strip()

            if ip not in ip_addresses:
                ip_addresses.append(ip)

    summary = {
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "password_changes": password_changes,
        "ip_addresses": ip_addresses
    }

    return summary
def count_failed_attempts_per_ip(log_text):
    """
    Count how many failed login attempts came from each IP.
    """

    failed_attempts = {}

    lines = log_text.split("\n")

    for line in lines:

        if "LOGIN FAILED" in line and "ip=" in line:

            ip = line.split("ip=")[1].strip()

            if ip in failed_attempts:
                failed_attempts[ip] += 1
            else:
                failed_attempts[ip] = 1

    return failed_attempts
def find_targeted_users(log_text):
    """
    Count failed login attempts for each user.
    """

    users = {}

    lines = log_text.split("\n")

    for line in lines:

        if "LOGIN FAILED" in line and "user=" in line:

            username = line.split("user=")[1].split()[0]

            if username in users:
                users[username] += 1
            else:
                users[username] = 1

    return users
def find_suspicious_ips(failed_attempts, threshold=3):
    """
    Return IP addresses with failed attempts above the threshold.
    """

    suspicious_ips = []

    for ip, attempts in failed_attempts.items():

        if attempts >= threshold:
            suspicious_ips.append(ip)

    return suspicious_ips
def save_report(report_text):
    """
    Save the AI-generated report into the reports folder.
    """

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    filename = f"reports/security_report_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as file:
        file.write(report_text)

    return filename
def view_reports():
    """
    Display all saved reports.
    """

    report_folder = "reports"

    reports = os.listdir(report_folder)

    if not reports:
        print("\nNo reports found.\n")
        return

    print("\n========== SAVED REPORTS ==========\n")

    for index, report in enumerate(reports, start=1):
        print(f"{index}. {report}")
def calculate_risk_score(summary, failed_attempts, targeted_users, suspicious_ips):
    """
    Calculate a security risk score based on predefined rules.
    """

    score = 0
    reasons = []

    # Rule 1
    if summary["failed_logins"] >= 3:
        score += 30
        reasons.append("Multiple failed login attempts detected.")

    # Rule 2
    if len(suspicious_ips) > 0:
        score += 25
        reasons.append("Suspicious IP addresses detected.")

    # Rule 3
    if "admin" in targeted_users:
        score += 25
        reasons.append("Administrative account targeted.")

    # Rule 4
    if summary["password_changes"] > 0:
        score += 20
        reasons.append("Password change detected after suspicious activity.")

    return score, reasons
def get_severity(score):
    """
    Convert a numerical score into a severity level.
    """

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    else:
        return "LOW"