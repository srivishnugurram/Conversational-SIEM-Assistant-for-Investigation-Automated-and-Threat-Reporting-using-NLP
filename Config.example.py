# =============================================
# CONFIGURATION TEMPLATE
# =============================================
# 1. Copy this file to config.py
# 2. Fill in your actual credentials
# 3. config.py is in .gitignore — never uploaded
# =============================================

# Wazuh Manager Settings
WAZUH_URL = "https://localhost:55000"   # Change if Wazuh is on another machine
USERNAME  = "your_wazuh_username"        # Wazuh API username
PASSWORD  = "your_wazuh_password"        # Wazuh API password

# Groq AI API Key
# Get free key from: https://console.groq.com
GROQ_API_KEY = "your_groq_api_key_here"

# Network Settings (for capture.py on Windows)
KALI_IP   = "your_kali_ip_address"      # Run 'ip a' on Kali to find this
KALI_PORT = "5050"
