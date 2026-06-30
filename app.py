from tools import (
    read_log_file,
    parse_logs,
    count_failed_attempts_per_ip,
    find_targeted_users,
    find_suspicious_ips,
    save_report,
    view_reports,
)

from agent import analyze_logs


def analyze_server_logs():

    print("\nReading Server Logs...\n")

    logs = read_log_file()

    summary = parse_logs(logs)

    failed_attempts = count_failed_attempts_per_ip(logs)

    targeted_users = find_targeted_users(logs)

    suspicious_ips = find_suspicious_ips(failed_attempts)

    print("\n========== LOG SUMMARY ==========\n")

    print(f"Failed Logins      : {summary['failed_logins']}")
    print(f"Successful Logins  : {summary['successful_logins']}")
    print(f"Password Changes   : {summary['password_changes']}")
    print(f"IP Addresses       : {', '.join(summary['ip_addresses'])}")

    print("\n========== FAILED ATTEMPTS PER IP ==========\n")

    for ip, count in failed_attempts.items():
        print(f"{ip} -> {count}")

    print("\n========== TARGETED USERS ==========\n")

    for user, count in targeted_users.items():
        print(f"{user} -> {count}")

    print("\n========== SUSPICIOUS IPS ==========\n")

    if suspicious_ips:
        for ip in suspicious_ips:
            print(ip)
    else:
        print("No suspicious IPs detected.")

    print("\n========== AI ANALYSIS ==========\n")

    analysis = analyze_logs(
        logs,
        summary,
        failed_attempts,
        targeted_users,
        suspicious_ips,
    )

    print(analysis)

    report_path = save_report(analysis)

    print("\n========================================")
    print("REPORT SAVED SUCCESSFULLY")
    print(f"Location: {report_path}")
    print("========================================")


while True:

    print("\n" + "=" * 50)
    print("        AI SECURITY AGENT")
    print("=" * 50)

    print("1. Analyze Server Logs")
    print("2. View Saved Reports")
    print("3. Exit")

    choice = input("\nChoose an option: ")

    if choice == "1":

        analyze_server_logs()

    elif choice == "2":

        view_reports()

    elif choice == "3":

        print("\nGoodbye!")
        break

    else:

        print("\nInvalid option. Please try again.")