from tools import (
    read_log_file,
    parse_logs,
    count_failed_attempts_per_ip,
    find_targeted_users,
    find_suspicious_ips,
)
from agent import analyze_logs

print("=" * 40)
print("AI SECURITY AGENT")
print("=" * 40)

print("\nReading Server Logs...\n")

logs = read_log_file()

summary = parse_logs(logs)
failed_attempts = count_failed_attempts_per_ip(logs)

targeted_users = find_targeted_users(logs)

suspicious_ips = find_suspicious_ips(failed_attempts)

print("========== LOG SUMMARY ==========\n")

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
    suspicious_ips
)

print(analysis) 