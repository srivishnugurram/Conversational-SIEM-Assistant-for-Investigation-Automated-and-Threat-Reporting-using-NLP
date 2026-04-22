"""
groq_assistant.py — Standalone Groq AI Assistant Test
-------------------------------------------------------
Tests the Groq AI integration independently from the main app.
Fetches Wazuh alerts and asks the LLM test questions.

Usage:
    python3 groq_assistant.py
"""

import requests
import urllib3
from groq import Groq

urllib3.disable_warnings()

# =============================================
# 🔧 CONFIGURATION
# =============================================
try:
    from config import WAZUH_URL, USERNAME, PASSWORD, GROQ_API_KEY
except ImportError:
    WAZUH_URL    = "https://localhost:55000"
    USERNAME     = "your_wazuh_username"
    PASSWORD     = "your_wazuh_password"
    GROQ_API_KEY = "your_groq_api_key"

client = Groq(api_key=GROQ_API_KEY)


def get_wazuh_token():
    """Login to Wazuh and get token"""
    response = requests.post(
        f"{WAZUH_URL}/security/user/authenticate",
        auth=(USERNAME, PASSWORD),
        verify=False
    )
    if response.status_code == 200:
        return response.json()["data"]["token"]
    print("❌ Wazuh login failed!")
    return None


def get_alerts(token, limit=20):
    """Fetch alerts from Wazuh log file"""
    alerts = []
    try:
        with open("/var/ossec/logs/alerts/alerts.log", "r") as f:
            content = f.read()

        raw_alerts = content.strip().split("** Alert ")
        raw_alerts = [a for a in raw_alerts if a.strip()]

        for raw in raw_alerts[-limit:]:
            lines = raw.strip().split("\n")
            alert = {
                "rule":  {"description": "N/A", "level": "0", "id": "N/A"},
                "agent": {"name": "N/A"},
                "timestamp": "N/A"
            }
            for line in lines:
                if "->" in line:
                    alert["agent"]["name"] = line.split("->")[0].strip().split(" ")[-1]
                    break
            for line in lines:
                if "Rule:" in line and "->" in line:
                    try:
                        alert["rule"]["id"]          = line.split("Rule:")[1].split("(")[0].strip()
                        alert["rule"]["level"]       = line.split("level")[1].split(")")[0].strip()
                        alert["rule"]["description"] = line.split("->")[1].strip().strip("'")
                    except:
                        pass
                    break
            alerts.append(alert)
    except Exception as e:
        print(f"Error reading alerts: {e}")
    return alerts


def format_alerts_for_llm(alerts):
    """Convert alerts to readable text for LLM"""
    if not alerts:
        return "No alerts currently available."
    formatted = ""
    for i, alert in enumerate(alerts, 1):
        formatted += f"""
Alert {i}:
  - Description: {alert.get('rule', {}).get('description', 'N/A')}
  - Severity Level: {alert.get('rule', {}).get('level', 'N/A')}
  - Agent/Machine: {alert.get('agent', {}).get('name', 'N/A')}
  - Timestamp: {alert.get('timestamp', 'N/A')}
  - Rule ID: {alert.get('rule', {}).get('id', 'N/A')}
"""
    return formatted


def ask_assistant(user_question, alerts_text):
    """Send question and alerts to Groq LLM"""
    system_prompt = """You are a cybersecurity analyst assistant integrated with a Wazuh SIEM system.
Your job is to help security analysts investigate threats by answering their questions
based on real security alerts. Be clear, concise, and highlight critical threats."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": f"Current Wazuh Alerts:\n{alerts_text}\n\nQuestion: {user_question}"}
        ],
        temperature=0.3,
        max_tokens=1024
    )
    return response.choices[0].message.content


if __name__ == "__main__":
    print("=" * 50)
    print("   Conversational SIEM Assistant - Test")
    print("=" * 50)

    print("\n🔌 Connecting to Wazuh...")
    token = get_wazuh_token()

    if not token:
        print("❌ Could not connect to Wazuh.")
        exit()

    print("✅ Connected!")
    print("📥 Fetching alerts...")
    alerts      = get_alerts(token, limit=20)
    alerts_text = format_alerts_for_llm(alerts)
    print(f"✅ Fetched {len(alerts)} alerts!\n")

    # Test questions
    test_questions = [
        "Give me a summary of the current security status",
        "Are there any critical threats I should be worried about?",
        "Which machine has the most alerts?"
    ]

    for question in test_questions:
        print(f"\n🧑 Analyst: {question}")
        print("🤖 Assistant:", end=" ")
        answer = ask_assistant(question, alerts_text)
        print(answer)
        print("-" * 50)
