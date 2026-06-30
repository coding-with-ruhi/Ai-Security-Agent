from tools import read_log_file, parse_logs
from agent import analyze_logs

print("=" * 40)
print("AI SECURITY AGENT")
print("=" * 40)

print("\nReading Server Logs...\n")

logs = read_log_file()

summary = parse_logs(logs)

print("========== LOG SUMMARY ==========\n")

print(f"Failed Logins      : {summary['failed_logins']}")
print(f"Successful Logins  : {summary['successful_logins']}")
print(f"Password Changes   : {summary['password_changes']}")
print(f"IP Addresses       : {', '.join(summary['ip_addresses'])}")

print("\n========== AI ANALYSIS ==========\n")

analysis = analyze_logs(logs)

print(analysis) 