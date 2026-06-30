from tools import (
    read_log_file,
    parse_logs,
    count_failed_attempts_per_ip,
    find_targeted_users,
    find_suspicious_ips,
    calculate_risk_score,
    get_severity,
    show_security_alert,
    recommend_actions,
    get_user_approval,
    execute_action,
    save_report,
    view_reports,
)

from agent import analyze_logs


# =====================================================
# MAIN ANALYSIS FUNCTION
# =====================================================

def analyze_server_logs():

    print("\n" + "=" * 60)
    print("READING SERVER LOGS...")
    print("=" * 60)

    # ---------------------------------
    # Read Logs
    # ---------------------------------

    logs = read_log_file()

    if logs.startswith("Error"):
        print(logs)
        return

    # ---------------------------------
    # Parse Logs
    # ---------------------------------

    summary = parse_logs(logs)

    failed_attempts = count_failed_attempts_per_ip(logs)

    targeted_users = find_targeted_users(logs)

    suspicious_ips = find_suspicious_ips(failed_attempts)

    # ---------------------------------
    # Calculate Risk
    # ---------------------------------

    risk_score, reasons = calculate_risk_score(
        summary,
        failed_attempts,
        targeted_users,
        suspicious_ips,
    )

    severity = get_severity(risk_score)

    # ---------------------------------
    # Display Parsed Information
    # ---------------------------------

    print("\n========== LOG SUMMARY ==========\n")

    print(f"Failed Logins      : {summary['failed_logins']}")
    print(f"Successful Logins  : {summary['successful_logins']}")
    print(f"Password Changes   : {summary['password_changes']}")
    print(f"IP Addresses       : {', '.join(summary['ip_addresses'])}")

    # ---------------------------------

    print("\n========== FAILED ATTEMPTS PER IP ==========\n")

    if failed_attempts:

        for ip, count in failed_attempts.items():
            print(f"{ip} -> {count}")

    else:

        print("No failed login attempts.")

    # ---------------------------------

    print("\n========== TARGETED USERS ==========\n")

    if targeted_users:

        for user, count in targeted_users.items():
            print(f"{user} -> {count}")

    else:

        print("No targeted users.")

    # ---------------------------------

    print("\n========== SUSPICIOUS IPS ==========\n")

    if suspicious_ips:

        for ip in suspicious_ips:
            print(ip)

    else:

        print("No suspicious IPs detected.")

    # ---------------------------------
    # Risk Assessment
    # ---------------------------------

    print("\n========== RISK ASSESSMENT ==========\n")

    print(f"Risk Score : {risk_score}/100")
    print(f"Severity   : {severity}")

    print("\nReasons:")

    if reasons:

        for reason in reasons:
            print(f"- {reason}")

    else:

        print("No major security concerns detected.")

    # ---------------------------------
    # AI Analysis
    # ---------------------------------

    print("\n========== AI ANALYSIS ==========\n")

    analysis = analyze_logs(
        logs,
        summary,
        failed_attempts,
        targeted_users,
        suspicious_ips,
        risk_score,
        severity,
        reasons,
    )

    print(analysis)

    # =====================================================
    # DECISION ENGINE
    # =====================================================

    show_security_alert(
        severity,
        risk_score,
    )

    recommend_actions()

    selected_action = get_user_approval()

    action_taken = execute_action(
        selected_action,
        suspicious_ips,
    )

    # =====================================================
    # SAVE REPORT
    # =====================================================

    report_path = save_report(
        analysis,
        risk_score,
        severity,
        action_taken,
    )

    print("\n" + "=" * 60)
    print("REPORT SAVED SUCCESSFULLY")
    print(f"Location : {report_path}")
    print("=" * 60)


# =====================================================
# MAIN MENU
# =====================================================

def main():

    while True:

        print("\n" + "=" * 60)
        print("           AI SECURITY AGENT")
        print("=" * 60)

        print("1. Analyze Server Logs")
        print("2. View Saved Reports")
        print("3. Exit")

        choice = input("\nChoose an option: ").strip()

        if choice == "1":

            analyze_server_logs()

        elif choice == "2":

            view_reports()

        elif choice == "3":

            print("\nThank you for using AI Security Agent.")
            break

        else:

            print("\nInvalid choice. Please enter 1, 2 or 3.")


# =====================================================
# ENTRY POINT
# =====================================================

if __name__ == "__main__":
    main()