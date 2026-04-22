import streamlit as st
import requests
import urllib3
from groq import Groq
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
import os

urllib3.disable_warnings()

# =============================================
# 🔧 CONFIGURATION
# Copy config.example.py to config.py and
# fill in your actual credentials
# =============================================
try:
    from config import WAZUH_URL, USERNAME, PASSWORD, GROQ_API_KEY
except ImportError:
    WAZUH_URL    = os.environ.get("WAZUH_URL",    "https://localhost:55000")
    USERNAME     = os.environ.get("WAZUH_USER",   "your_wazuh_username")
    PASSWORD     = os.environ.get("WAZUH_PASS",   "your_wazuh_password")
    GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "your_groq_api_key")

# ── App Login Credentials ─────────────────────
APP_USERS = {
    "admin":   "admin@123"
}

# ── Page Config ───────────────────────────────
st.set_page_config(
    page_title="Conversational SIEM Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS ────────────────────────────────
st.markdown("""
<style>
    .stApp { background-color: #0d1117; color: #e6edf3; }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #161b22 0%, #0d1117 100%);
        border-right: 1px solid #30363d;
    }
    [data-testid="stMetric"] {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 15px;
    }
    .stTabs [data-baseweb="tab-list"] {
        background-color: #161b22;
        border-radius: 8px;
        padding: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        color: #8b949e;
        border-radius: 6px;
        font-weight: 600;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1f6feb !important;
        color: white !important;
    }
    .stButton > button {
        background: #21262d;
        color: #e6edf3;
        border: 1px solid #30363d;
        border-radius: 8px;
        transition: all 0.2s;
    }
    .stButton > button:hover {
        background: #1f6feb;
        border-color: #1f6feb;
        color: white;
    }
    [data-testid="stChatMessage"] {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        margin-bottom: 8px;
    }
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    hr { border-color: #30363d; }
    h1 { color: #e6edf3 !important; }
    h2, h3 { color: #c9d1d9 !important; }
</style>
""", unsafe_allow_html=True)


# ── Login Page ────────────────────────────────
def show_login():
    st.markdown("""
    <div style='text-align: center; padding: 40px 0 20px 0;'>
        <div style='font-size: 64px;'>🛡️</div>
        <h1 style='color: #e6edf3; font-size: 2.2rem; margin: 0;'>Conversational SIEM Assistant</h1>
        <p style='color: #8b949e; font-size: 1rem; margin-top: 8px;'>AI-Powered Security Investigation Platform</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.markdown("<div style='background:#161b22; border:1px solid #30363d; border-radius:16px; padding:32px;'>", unsafe_allow_html=True)
        st.markdown("### 🔐 Sign In")
        username = st.text_input("Username", placeholder="Enter username")
        password = st.text_input("Password", type="password", placeholder="Enter password")

        if st.button("Sign In", use_container_width=True):
            if username in APP_USERS and APP_USERS[username] == password:
                st.session_state.logged_in = True
                st.session_state.current_user = username
                st.rerun()
            else:
                st.error("Invalid username or password")
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<p style='text-align:center; color:#8b949e; font-size:0.8rem; margin-top:16px;'>Default: admin / siem@123</p>", unsafe_allow_html=True)


# ── Check Login ───────────────────────────────
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    show_login()
    st.stop()

# ── Groq Client ───────────────────────────────
client = Groq(api_key=GROQ_API_KEY)


# ── Wazuh Functions ───────────────────────────
def get_wazuh_token():
    try:
        response = requests.post(
            f"{WAZUH_URL}/security/user/authenticate",
            auth=(USERNAME, PASSWORD),
            verify=False
        )
        if response.status_code == 200:
            return response.json()["data"]["token"]
    except:
        pass
    return None


def get_alerts(token, limit=100):
    alerts = []
    try:
        with open("/var/ossec/logs/alerts/alerts.log", "r") as f:
            content = f.read()

        raw_alerts = content.strip().split("** Alert ")
        raw_alerts = [a for a in raw_alerts if a.strip()]

        for raw in raw_alerts[-limit:]:
            lines = raw.strip().split("\n")
            alert = {
                "rule": {"description": "N/A", "level": "0", "id": "N/A"},
                "agent": {"name": "N/A"},
                "timestamp": "N/A",
                "timestamp_dt": None
            }

            if lines:
                parts = lines[0].split(" ")
                alert["timestamp"] = parts[0] if parts else "N/A"
                try:
                    ts_str = " ".join(lines[1].split(" ")[:4]) if len(lines) > 1 else ""
                    alert["timestamp_dt"] = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S") if ts_str else None
                except:
                    pass

            for line in lines:
                if "->" in line:
                    agent_name = line.split("->")[0].strip().split(" ")[-1]
                    alert["agent"]["name"] = agent_name
                    break

            for line in lines:
                if "Rule:" in line and "->" in line:
                    try:
                        rule_id     = line.split("Rule:")[1].split("(")[0].strip()
                        level       = line.split("level")[1].split(")")[0].strip()
                        description = line.split("->")[1].strip().strip("'")
                        alert["rule"]["id"]          = rule_id
                        alert["rule"]["level"]       = level
                        alert["rule"]["description"] = description
                    except:
                        pass
                    break

            alerts.append(alert)

    except Exception as e:
        print(f"Error reading alerts log: {e}")

    return alerts


def get_agents(token):
    try:
        headers  = {"Authorization": f"Bearer {token}"}
        response = requests.get(
            f"{WAZUH_URL}/agents",
            headers=headers,
            verify=False,
            params={"limit": 10}
        )
        if response.status_code == 200:
            return response.json().get("data", {}).get("affected_items", [])
    except:
        pass
    return []


def get_level_label(a):
    lvl = int(a.get('rule', {}).get('level', 0) or 0)
    return "HIGH" if lvl >= 10 else "MEDIUM" if lvl >= 5 else "LOW"


def format_alerts(alerts):
    if not alerts:
        return "No alerts currently available."
    formatted = ""
    for i, alert in enumerate(alerts, 1):
        level    = int(alert.get('rule', {}).get('level', 0) or 0)
        severity = "HIGH" if level >= 10 else "MEDIUM" if level >= 5 else "LOW"
        formatted += f"""
Alert {i}:
  - Description: {alert.get('rule', {}).get('description', 'N/A')}
  - Severity: {severity} (Level {level})
  - Agent/Machine: {alert.get('agent', {}).get('name', 'N/A')}
  - Timestamp: {alert.get('timestamp', 'N/A')}
  - Rule ID: {alert.get('rule', {}).get('id', 'N/A')}
"""
    return formatted


# ── LLM Function ─────────────────────────────
def ask_assistant(user_question, alerts_text, chat_history):
    system_prompt = """You are an expert cybersecurity analyst assistant integrated with a Wazuh SIEM system.
Your job is to help security analysts investigate threats by answering questions based on real security alerts.

You can handle these types of queries:
- Summary of current security status
- Failed login / brute force attempts
- Port scan / reconnaissance detection
- User account creation or deletion
- Privilege escalation (sudo/root access)
- Which machine/agent has the most alerts
- High or critical severity threats
- Timeline of recent events
- Recommendations for remediation
- Comparing activity between agents
- What happened in the last hour/day

When answering:
- Be clear, structured, and concise
- Use bullet points for lists
- Highlight CRITICAL or HIGH severity alerts urgently
- Always mention affected machine names
- Give specific next steps when threats are found
- If no relevant alerts found, say so clearly and suggest what to monitor
"""
    messages = [{"role": "system", "content": system_prompt}]
    for msg in chat_history[-10:]:
        messages.append({"role": msg["role"], "content": msg["content"]})

    messages.append({
        "role": "user",
        "content": f"""Current Wazuh SIEM Alerts:
{alerts_text}

Analyst Question: {user_question}

Please analyze and respond as a cybersecurity expert."""
    })

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=messages,
        temperature=0.2,
        max_tokens=1500
    )
    return response.choices[0].message.content


# ── Sidebar ───────────────────────────────────
with st.sidebar:
    st.markdown(f"""
    <div style='text-align:center; padding: 10px 0;'>
        <div style='font-size: 40px;'>🛡️</div>
        <div style='color:#e6edf3; font-weight:700; font-size:1rem;'>SIEM Assistant</div>
        <div style='color:#8b949e; font-size:0.75rem;'>Logged in as: {st.session_state.current_user}</div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()
    auto_refresh = st.toggle("🔄 Auto Refresh (30s)", value=False)
    token = get_wazuh_token()

    if token:
        st.success("✅ Wazuh Connected")
        agents = get_agents(token)
        alerts = get_alerts(token, limit=100)

        st.markdown("**🖥️ Agents**")
        if agents:
            for agent in agents:
                status = agent.get("status", "unknown")
                icon   = "🟢" if status == "active" else "🔴"
                st.write(f"{icon} {agent.get('name', 'Unknown')} — {status}")

        high   = sum(1 for a in alerts if int(a.get('rule', {}).get('level', 0) or 0) >= 10)
        medium = sum(1 for a in alerts if 5 <= int(a.get('rule', {}).get('level', 0) or 0) < 10)
        low    = sum(1 for a in alerts if int(a.get('rule', {}).get('level', 0) or 0) < 5)

        st.markdown("**🚨 Alert Summary**")
        c1, c2, c3 = st.columns(3)
        c1.metric("High",   high)
        c2.metric("Med",    medium)
        c3.metric("Low",    low)

        if high > 0:
            st.error(f"⚠️ {high} HIGH severity alert(s) require attention!")
    else:
        st.error("❌ Wazuh Disconnected")
        alerts = []
        high = medium = low = 0

    st.divider()
    st.markdown("**🔍 Filter Alerts**")
    severity_filter = st.multiselect(
        "By Severity",
        options=["HIGH", "MEDIUM", "LOW"],
        default=["HIGH", "MEDIUM", "LOW"]
    )
    agent_names   = list(set(a.get("agent", {}).get("name", "N/A") for a in alerts)) if alerts else []
    agent_filter  = st.multiselect("By Agent", options=agent_names, default=agent_names)

    st.divider()
    st.markdown("**⚡ Quick Questions**")
    quick_questions = [
        "Summarize current security status",
        "Any critical threats right now?",
        "Show all failed login attempts",
        "Which machine has the most alerts?",
        "Any privilege escalation detected?",
        "Show reconnaissance or port scans",
        "What happened in the last hour?",
        "What should I investigate first?",
        "Compare activity between agents",
        "Give me a full threat report summary"
    ]
    for q in quick_questions:
        if st.button(q, use_container_width=True):
            st.session_state.quick_question = q

    st.divider()
    if st.button("📄 Generate PDF Report", use_container_width=True):
        with st.spinner("Generating report..."):
            try:
                from report import generate_report
                path = generate_report(alerts, st.session_state.get("messages", []))
                with open(path, "rb") as f:
                    st.download_button(
                        label="⬇️ Download PDF Report",
                        data=f,
                        file_name=f"siem_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
            except Exception as e:
                st.error(f"Report error: {e}")

    if st.button("📊 Export Alerts CSV", use_container_width=True):
        if alerts:
            rows = []
            for a in alerts:
                level = int(a.get('rule', {}).get('level', 0) or 0)
                rows.append({
                    "Timestamp":   a.get("timestamp", "N/A"),
                    "Severity":    "HIGH" if level >= 10 else "MEDIUM" if level >= 5 else "LOW",
                    "Level":       level,
                    "Agent":       a.get("agent", {}).get("name", "N/A"),
                    "Description": a.get("rule", {}).get("description", "N/A"),
                    "Rule ID":     a.get("rule", {}).get("id", "N/A")
                })
            df  = pd.DataFrame(rows)
            csv = df.to_csv(index=False)
            st.download_button(
                label="⬇️ Download CSV",
                data=csv,
                file_name=f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )

    if st.button("🗑️ Clear Chat", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

    if st.button("🚪 Logout", use_container_width=True):
        st.session_state.logged_in     = False
        st.session_state.current_user  = None
        st.session_state.messages      = []
        st.rerun()

    st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")


# ── Apply Filters ─────────────────────────────
if alerts:
    if not severity_filter and not agent_filter:
        filtered_alerts = alerts
    elif not agent_filter:
        filtered_alerts = [a for a in alerts if get_level_label(a) in severity_filter]
    elif not severity_filter:
        filtered_alerts = [a for a in alerts if a.get("agent", {}).get("name", "N/A") in agent_filter]
    else:
        filtered_alerts = [
            a for a in alerts
            if get_level_label(a) in severity_filter
            and a.get("agent", {}).get("name", "N/A") in agent_filter
        ]
else:
    filtered_alerts = []


# ── Main Header ───────────────────────────────
st.markdown("""
<div style='display:flex; align-items:center; gap:12px; margin-bottom:8px;'>
    <span style='font-size:2rem;'>🛡️</span>
    <div>
        <h1 style='margin:0; font-size:1.8rem;'>Conversational SIEM Assistant</h1>
        <p style='margin:0; color:#8b949e; font-size:0.9rem;'>AI-powered threat investigation using Wazuh SIEM</p>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Tabs ──────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs(["💬 Chat", "📊 Dashboard", "⏱️ Timeline", "📋 Alert Log"])


# ── TAB 1: Chat ───────────────────────────────
with tab1:
    if "messages" not in st.session_state:
        st.session_state.messages = []

    if not st.session_state.messages:
        st.markdown("""
        <div style='background:#161b22; border:1px solid #30363d; border-radius:12px; padding:20px; margin-bottom:16px;'>
            <h4 style='margin:0 0 8px 0; color:#58a6ff;'>👋 Welcome to the SIEM Assistant!</h4>
            <p style='margin:0; color:#8b949e;'>Ask me anything about your security alerts. Try the quick questions on the left, or type your own query below.</p>
            <br/>
            <p style='margin:0; color:#8b949e; font-size:0.85rem;'>Examples: "Show failed logins", "Any critical threats?", "What should I investigate first?"</p>
        </div>
        """, unsafe_allow_html=True)

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    if "quick_question" in st.session_state and st.session_state.quick_question:
        prompt = st.session_state.quick_question
        st.session_state.quick_question = None
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        with st.chat_message("assistant"):
            with st.spinner("🔍 Analyzing security alerts..."):
                alerts_text = format_alerts(filtered_alerts)
                response    = ask_assistant(prompt, alerts_text, st.session_state.messages[:-1])
            st.markdown(response)
        st.session_state.messages.append({"role": "assistant", "content": response})
        st.rerun()

    if prompt := st.chat_input("Ask about your security alerts..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        with st.chat_message("assistant"):
            with st.spinner("🔍 Analyzing security alerts..."):
                alerts_text = format_alerts(filtered_alerts)
                response    = ask_assistant(prompt, alerts_text, st.session_state.messages[:-1])
            st.markdown(response)
        st.session_state.messages.append({"role": "assistant", "content": response})
        st.rerun()


# ── TAB 2: Dashboard ──────────────────────────
with tab2:
    st.subheader("📊 Real-Time Threat Dashboard")

    if auto_refresh:
        st.info("🔄 Auto-refreshing every 30 seconds...")

    if alerts:
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Alerts",    len(alerts))
        col2.metric("🔴 High",         high)
        col3.metric("🟡 Medium",       medium)
        col4.metric("🟢 Low",          low)

        st.divider()
        chart1, chart2 = st.columns(2)

        with chart1:
            st.markdown("#### Severity Distribution")
            pie_df  = pd.DataFrame({"Severity": ["High", "Medium", "Low"], "Count": [high, medium, low]})
            fig_pie = px.pie(
                pie_df, names="Severity", values="Count",
                color="Severity",
                color_discrete_map={"High": "#f85149", "Medium": "#e3b341", "Low": "#3fb950"},
                hole=0.45
            )
            fig_pie.update_traces(textposition="inside", textinfo="percent+label")
            fig_pie.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#c9d1d9", showlegend=True,
                margin=dict(t=20, b=20, l=20, r=20)
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        with chart2:
            st.markdown("#### Alerts per Agent")
            agent_counts = {}
            for a in alerts:
                name = a.get("agent", {}).get("name", "Unknown")
                agent_counts[name] = agent_counts.get(name, 0) + 1
            bar_df  = pd.DataFrame({"Agent": list(agent_counts.keys()), "Alerts": list(agent_counts.values())})
            fig_bar = px.bar(
                bar_df, x="Agent", y="Alerts", color="Alerts",
                color_continuous_scale=["#3fb950", "#e3b341", "#f85149"],
                text="Alerts"
            )
            fig_bar.update_traces(textposition="outside")
            fig_bar.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#c9d1d9", margin=dict(t=20, b=20, l=20, r=20),
                coloraxis_showscale=False
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        st.markdown("#### Top Alert Types")
        desc_counts = {}
        for a in alerts:
            desc = a.get("rule", {}).get("description", "Unknown")
            desc_counts[desc] = desc_counts.get(desc, 0) + 1
        top     = sorted(desc_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        top_df  = pd.DataFrame(top, columns=["Alert Type", "Count"])
        fig_top = px.bar(
            top_df, x="Count", y="Alert Type", orientation="h",
            color="Count", color_continuous_scale=["#3fb950", "#e3b341", "#f85149"],
            text="Count"
        )
        fig_top.update_traces(textposition="outside")
        fig_top.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#c9d1d9", height=350,
            margin=dict(t=20, b=20, l=20, r=20),
            coloraxis_showscale=False
        )
        st.plotly_chart(fig_top, use_container_width=True)
    else:
        st.info("No alerts available. Make sure your Wazuh agent is active.")


# ── TAB 3: Timeline ───────────────────────────
with tab3:
    st.subheader("⏱️ Threat Timeline")
    st.caption("Alerts plotted over time")

    timeline_alerts = [a for a in alerts if a.get("timestamp_dt") is not None]

    if timeline_alerts:
        rows = []
        for a in timeline_alerts:
            level = int(a.get('rule', {}).get('level', 0) or 0)
            rows.append({
                "Time":        a["timestamp_dt"],
                "Severity":    "HIGH" if level >= 10 else "MEDIUM" if level >= 5 else "LOW",
                "Level":       level,
                "Agent":       a.get("agent", {}).get("name", "N/A"),
                "Description": a.get("rule", {}).get("description", "N/A")
            })

        df_time = pd.DataFrame(rows).sort_values("Time")

        st.markdown("#### Alert Activity Over Time")
        df_time["Hour"] = df_time["Time"].dt.strftime("%H:%M")
        hourly   = df_time.groupby(["Hour", "Severity"]).size().reset_index(name="Count")
        fig_line = px.line(
            hourly, x="Hour", y="Count", color="Severity",
            color_discrete_map={"HIGH": "#f85149", "MEDIUM": "#e3b341", "LOW": "#3fb950"},
            markers=True, line_shape="spline"
        )
        fig_line.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#c9d1d9", height=300,
            margin=dict(t=20, b=20, l=20, r=20),
            xaxis=dict(gridcolor="#21262d"),
            yaxis=dict(gridcolor="#21262d")
        )
        st.plotly_chart(fig_line, use_container_width=True)

        st.markdown("#### Alert Scatter Timeline")
        fig_scatter = px.scatter(
            df_time, x="Time", y="Agent",
            color="Severity", size="Level",
            hover_data=["Description", "Level"],
            color_discrete_map={"HIGH": "#f85149", "MEDIUM": "#e3b341", "LOW": "#3fb950"},
            size_max=20
        )
        fig_scatter.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#c9d1d9", height=350,
            margin=dict(t=20, b=20, l=20, r=20),
            xaxis=dict(gridcolor="#21262d"),
            yaxis=dict(gridcolor="#21262d")
        )
        st.plotly_chart(fig_scatter, use_container_width=True)
    else:
        st.info("Timeline data not available.")
        if alerts:
            st.markdown("#### Alert Count by Agent")
            agent_counts = {}
            for a in alerts:
                name = a.get("agent", {}).get("name", "Unknown")
                agent_counts[name] = agent_counts.get(name, 0) + 1
            fallback_df = pd.DataFrame({"Agent": list(agent_counts.keys()), "Count": list(agent_counts.values())})
            st.bar_chart(fallback_df.set_index("Agent"))


# ── TAB 4: Alert Log ──────────────────────────
with tab4:
    st.subheader("📋 Alert Log")
    st.caption(f"Showing {len(filtered_alerts)} of {len(alerts)} total alerts")

    if filtered_alerts:
        rows = []
        for a in reversed(filtered_alerts):
            level    = int(a.get('rule', {}).get('level', 0) or 0)
            severity = "HIGH" if level >= 10 else "MEDIUM" if level >= 5 else "LOW"
            rows.append({
                "Timestamp":   a.get("timestamp", "N/A"),
                "Severity":    severity,
                "Level":       level,
                "Agent":       a.get("agent", {}).get("name", "N/A"),
                "Description": a.get("rule", {}).get("description", "N/A"),
                "Rule ID":     a.get("rule", {}).get("id", "N/A")
            })
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, height=550)
    else:
        st.info("No alerts match your current filters.")


# ── Auto Refresh ──────────────────────────────
if auto_refresh:
    time.sleep(30)
    st.rerun()
