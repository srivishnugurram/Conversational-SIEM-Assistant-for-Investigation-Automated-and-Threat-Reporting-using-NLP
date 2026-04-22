"""
test_wazuh.py — Wazuh API Connection Test
------------------------------------------
Tests the connection to the Wazuh REST API,
fetches connected agents and latest alerts.

Usage:
    python3 test_wazuh.py
"""

import requests
import json
import urllib3

urllib3.disable_warnings()

# =============================================
# 🔧 CONFIGURATION
# =============================================
try:
    from config import WAZUH_URL, USERNAME, PASSWORD
except ImportError:
    WAZUH_URL = "https://localhost:55000"
    USERNAME  = "your_wazuh_username"
    PASSWORD  = "your_wazuh_password"


def get_token():
    """Login to Wazuh API and get access token"""
    try:
        response = requests.post(
            f"{WAZUH_URL}/security/user/authenticate",
            auth=(USERNAME, PASSWORD),
            verify=False
        )
        if response.status_code == 200:
            token = response.json()["data"]["token"]
            print("✅ Connected to Wazuh API successfully!")
            return token
        else:
            print(f"❌ Login failed! Status: {response.status_code}")
            print(response.text)
            return None
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return None


def get_alerts(token, limit=5):
    """Fetch latest alerts from Wazuh"""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(
            f"{WAZUH_URL}/alerts",
            headers=headers,
            verify=False,
            params={"limit": limit, "sort": "-timestamp"}
        )
        if response.status_code == 200:
            data   = response.json()
            alerts = data.get("data", {}).get("affected_items", [])
            print(f"✅ Fetched {len(alerts)} alerts from Wazuh!\n")
            return alerts
        else:
            print(f"❌ Failed to fetch alerts! Status: {response.status_code}")
            return []
    except Exception as e:
        print(f"❌ Error fetching alerts: {e}")
        return []


def get_agents(token):
    """Fetch connected agents"""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(
            f"{WAZUH_URL}/agents",
            headers=headers,
            verify=False,
            params={"limit": 10}
        )
        if response.status_code == 200:
            agents = response.json()["data"]["affected_items"]
            print(f"✅ Found {len(agents)} agent(s):\n")
            for agent in agents:
                print(f"   - {agent['name']} | IP: {agent.get('ip', 'N/A')} | Status: {agent['status']}")
            print()
            return agents
        else:
            print(f"❌ Failed to fetch agents! Status: {response.status_code}")
            return []
    except Exception as e:
        print(f"❌ Error fetching agents: {e}")
        return []


if __name__ == "__main__":
    print("=" * 50)
    print("   Wazuh API Connection Test")
    print("=" * 50)

    token = get_token()

    if token:
        print("\n📡 Connected Agents:")
        get_agents(token)

        print("🚨 Latest Alerts:")
        alerts = get_alerts(token, limit=5)

        if alerts:
            for i, alert in enumerate(alerts, 1):
                print(f"\n--- Alert {i} ---")
                print(f"  Rule:      {alert.get('rule', {}).get('description', 'N/A')}")
                print(f"  Level:     {alert.get('rule', {}).get('level', 'N/A')}")
                print(f"  Agent:     {alert.get('agent', {}).get('name', 'N/A')}")
                print(f"  Timestamp: {alert.get('timestamp', 'N/A')}")
        else:
            print("  No alerts found.")

    print("\n" + "=" * 50)
    print("   Test Complete")
    print("=" * 50)
