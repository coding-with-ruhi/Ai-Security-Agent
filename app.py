from tools import read_log_file
from agent import analyze_logs

print("===================================")
print(" AI SECURITY AGENT ")
print("===================================")

print("\nReading Server Logs...\n")

logs = read_log_file()

print(logs)

print("\nAnalyzing logs using Local AI...\n")

analysis = analyze_logs(logs)

print("========== AI ANALYSIS ==========\n")

print(analysis)