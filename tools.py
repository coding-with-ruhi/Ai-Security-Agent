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