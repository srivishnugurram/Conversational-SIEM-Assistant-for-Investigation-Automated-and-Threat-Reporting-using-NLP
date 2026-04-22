# 🛡️ Conversational SIEM Assistant



---

## 📌 Problem Statement

**SIH25173** — Traditional SIEM systems require security analysts to write complex query languages to investigate threats. This creates a barrier for non-expert users and slows down threat response time.

**Our Solution** — A conversational AI assistant that allows anyone to investigate security threats by simply typing questions in plain English.

---

## 🎯 What is This Project?

The **Conversational SIEM Assistant** combines **Natural Language Processing (NLP)**, **Large Language Models (LLM)**, and **Security Information & Event Management (SIEM)** to create an intelligent security investigation platform.

Instead of writing complex queries, security analysts can simply ask:
- *"Are there any critical threats right now?"*
- *"Show me all failed login attempts"*
- *"Which machine has the most alerts?"*
- *"What should I investigate first?"*

And get instant, AI-powered answers based on **real Wazuh security alerts**.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 **Secure Login** | Username/password authentication |
| 💬 **NLP Chat Interface** | Ask security questions in plain English |
| 📊 **Real-Time Dashboard** | Live pie charts, bar charts, alert metrics |
| ⏱️ **Threat Timeline** | Alerts plotted over time |
| 🔍 **Alert Filtering** | Filter by severity and agent |
| 📄 **PDF Report Generation** | Auto-generate professional threat reports |
| 📊 **CSV Export** | Export alerts as spreadsheet |
| 🔄 **Auto Refresh** | Dashboard updates every 30 seconds |
| 🖥️ **Agent Monitoring** | Live status of all Wazuh agents |
| 📸 **Intruder Detection** | Screenshot capture on failed login |

---

## 🏗️ System Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Windows Agent │────▶│  Wazuh Manager   │────▶│  alerts.log     │
│   (WIN10)       │     │  (Kali Linux)    │     │  (Real Events)  │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                                                          ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Streamlit     │◀────│  Python Backend  │◀────│  Alert Parser   │
│   Web UI        │     │  (app.py)        │     │  (get_alerts)   │
└────────┬────────┘     └────────┬─────────┘     └─────────────────┘
         │                       │
         │                       ▼
         │              ┌──────────────────┐
         │              │   Groq LLM API   │
         │              │ (LLaMA 3.3 70B)  │
         │              └──────────────────┘
         ▼
┌─────────────────┐
│  PDF/CSV Report │
└─────────────────┘
```

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| **SIEM Platform** | Wazuh 4.x |
| **Backend** | Python 3.13 |
| **Web Framework** | Streamlit |
| **AI Model** | LLaMA 3.3 70B via Groq API |
| **Charts** | Plotly Express |
| **PDF Generation** | FPDF2 |
| **Data Processing** | Pandas |
| **Screenshot Capture** | PowerShell + OpenCV |
| **Photo Server** | Flask |
| **OS (Manager)** | Kali Linux |
| **OS (Agent)** | Windows 10 |

---

## 📁 Project Structure

```
conversational-siem/
│
├── app.py                  # Main Streamlit web application
├── report.py               # PDF threat report generator
├── photo_server.py         # Receives intruder photos from Windows
├── capture.py              # Captures screenshot on failed login (Windows)
├── simulate_attack.py      # Simulates attack scenarios for demo
├── test_wazuh.py           # Wazuh API connection test
├── groq_assistant.py       # Standalone Groq AI test
├── config.example.py       # Configuration template
├── requirements.txt        # Python dependencies
├── .gitignore              # Git ignore rules
└── README.md               # Project documentation
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Kali Linux with Wazuh Manager installed
- Windows 10 machine with Wazuh Agent installed
- Python 3.10 or higher
- Free Groq API key from [console.groq.com](https://console.groq.com)

---

### Step 1 — Clone the Repository

```bash
git clone https://github.com/YourUsername/conversational-siem.git
cd conversational-siem
```

---

### Step 2 — Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

---

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

---

### Step 4 — Configure Credentials

```bash
cp config.example.py config.py
nano config.py
```

Fill in your actual values:
```python
WAZUH_URL    = "https://localhost:55000"
USERNAME     = "your_wazuh_username"
PASSWORD     = "your_wazuh_password"
GROQ_API_KEY = "your_groq_api_key"
KALI_IP      = "your_kali_ip_address"
```

---

### Step 5 — Set Alert Log Permissions

```bash
sudo chmod 644 /var/ossec/logs/alerts/alerts.log
sudo chmod 755 /var/ossec/logs/alerts/
```

---

### Step 6 — Run the Application

```bash
sudo $(which streamlit) run app.py
```

Open browser at: `http://localhost:8501`



---

## 📸 Intruder Detection Setup

### On Kali — Start Photo Receiver
```bash
python3 photo_server.py
```

### On Windows — Start Capture Script
```cmd
pip install Pillow requests
python capture.py
```

When a failed login is detected on Windows:
1. Screenshot is captured automatically
2. Sent to Kali SIEM server
3. Stored in `intruder_photos/` folder

---

## 🎭 Attack Simulation (Demo)

Run on Windows to simulate realistic attacks:
```cmd
python simulate_attack.py
```

This simulates:
- Failed login attempts
- Unauthorized user creation
- Port scan activity
- Suspicious file changes

---

## 💬 Example NLP Queries

```
"Summarize current security status"
"Show me all failed login attempts"
"Any critical threats right now?"
"Which machine has the most alerts?"
"Was there any privilege escalation?"
"Show reconnaissance or port scans"
"What happened in the last hour?"
"What should I investigate first?"
"Compare activity between agents"
"Give me a full threat report summary"
```

---

## 📊 Dashboard Screenshots

| Chat Interface | Threat Dashboard |
|---------------|-----------------|
| AI-powered Q&A | Real-time charts |

| Threat Timeline | Alert Log |
|----------------|-----------|
| Alerts over time | Filterable table |

---

## 🔬 Technical Analysis

The system uses the following analytical methods:

| Method | Purpose |
|--------|---------|
| **Threshold Classification** | Severity scoring (High/Medium/Low) |
| **Frequency Analysis** | Alert type distribution charts |
| **Time Series Analysis** | Timeline grouping by hour |
| **Statistical Counting** | Alert aggregation per agent |
| **NLP Intent Detection** | Understanding analyst questions |
| **LLM Summarization** | Converting raw alerts to insights |

---

## 🚀 Future Enhancements

- Elasticsearch integration for historical queries
- Email/SMS notifications for critical threats
- Machine learning anomaly detection
- Cloud deployment for remote access
- Multi-language support
- Mobile-friendly responsive UI
- Database for proper user authentication

---

## 👥 Team

- **Domain:** Cybersecurity + Artificial Intelligence
- **College:** Final Year Project


---

## 📄 License

This project is developed for academic and educational purposes as part of a Final Year Project.

---

## ⭐ If you found this useful, please give it a star!
