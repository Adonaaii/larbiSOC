from groq import Groq
from dotenv import load_dotenv
load_dotenv()

import os

api_key = os.getenv("GROQ_API_KEY")
client = Groq(api_key=api_key) if api_key else None

def generate_ai_summary(incident):
    if client is None:
        return ""


    prompt = f"""
    You are a SOC analyst.

    Analyze this security incident.

    IP Address: {incident['ip']}
    Failed Logins: {incident['failed_logins']}
    SQL Injection: {incident['sql_injection']}
    Scanner Activity: {incident['scanner_activity']}
    Severity: {incident['severity']}
    Threat Score: {incident['score']}

    Explain:
    1. What happened
    2. Risk level
    3. Recommended response
    4. Short analyst note
    """

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response.choices[0].message.content