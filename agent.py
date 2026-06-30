from ollama import chat
from prompts import SYSTEM_PROMPT


def analyze_logs(log_text):

    prompt = f"""
{SYSTEM_PROMPT}

Server Logs:

{log_text}
"""

    response = chat(
        model="llama3.2:3b",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response.message.content