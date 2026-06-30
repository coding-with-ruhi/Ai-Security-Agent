from pathlib import Path

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