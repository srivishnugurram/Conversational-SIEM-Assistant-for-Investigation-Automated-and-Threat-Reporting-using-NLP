"""
simulate_attack.py — Attack Simulation Script (Run on Windows Endpoint)
------------------------------------------------------------------------
Simulates realistic attack scenarios for demo and testing purposes.
Triggers Wazuh alerts and captures screenshots for each attack type.

Simulated Attacks:
    1. Failed Login Attempts   (Event ID 4625)
    2. Unauthorized User Creation
    3. Port Scan Activity
    4. Suspicious File Activity

Usage:
    python simulate_attack.py
"""

import subprocess
import time
import os
import requests
from datetime import datetime

# =============================================
# 🔧 CONFIGURATION
# Update KALI_IP before running
# =============================================
try:
    from config import KALI_IP, KALI_PORT, SAVE_FOLDER
except ImportError:
    KALI_IP     = "your_kali_ip_address"   # Run 'ip a' on Kali to find this
    KALI_PORT   = "5050"
    SAVE_FOLDER = "C:\\intruder_photos"

os.makedirs(SAVE_FOLDER, exist_ok=True)


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def capture_screenshot(label="attack"):
    """Capture screenshot using PowerShell"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = f"intruder_{label}_{timestamp}.png"
        filepath  = os.path.join(SAVE_FOLDER, filename)

        ps_cmd = f"""
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$screen   = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bitmap   = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
$bitmap.Save('{filepath}')
$graphics.Dispose()
$bitmap.Dispose()
"""
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15
        )

        if os.path.exists(filepath):
            log(f"✅ Screenshot saved: {filename}")
            return filepath
        return None
    except Exception as e:
        log(f"❌ Screenshot error: {e}")
        return None


def send_to_kali(filepath, attack_type):
    """Send screenshot to Kali SIEM server"""
    try:
        url = f"http://{KALI_IP}:{KALI_PORT}/upload"
        with open(filepath, "rb") as f:
            files = {"photo": (os.path.basename(filepath), f, "image/png")}
            data  = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type":      attack_type
            }
            response = requests.post(url, files=files, data=data, timeout=10)
        if response.status_code == 200:
            log(f"✅ Screenshot sent to SIEM!")
        else:
            log(f"⚠️ Server responded: {response.status_code}")
    except Exception as e:
        log(f"⚠️ Could not send: {e}")


def simulate_failed_logins():
    """Simulate multiple failed login attempts"""
    log("🚨 SIMULATING: Failed Login Attempts")
    for i in range(3):
        subprocess.run(
            ["net", "use", r"\\localhost\IPC$", "/user:hacker", "wrongpassword123"],
            capture_output=True, text=True
        )
        log(f"   Failed login attempt {i+1}/3")
        time.sleep(1)

    filepath = capture_screenshot("failed_login")
    if filepath:
        send_to_kali(filepath, "Failed Login Attack")


def simulate_user_creation():
    """Simulate unauthorized user creation"""
    log("🚨 SIMULATING: Unauthorized User Creation")
    subprocess.run(
        ["net", "user", "hacker_user", "Password123!", "/add"],
        capture_output=True, text=True
    )
    log("   Created user: hacker_user")
    time.sleep(1)

    filepath = capture_screenshot("user_creation")
    if filepath:
        send_to_kali(filepath, "Unauthorized User Creation")

    # Clean up
    time.sleep(2)
    subprocess.run(
        ["net", "user", "hacker_user", "/delete"],
        capture_output=True, text=True
    )
    log("   Cleaned up: deleted hacker_user")


def simulate_port_scan():
    """Simulate port scan activity"""
    log("🚨 SIMULATING: Port Scan Activity")
    ps_cmd = f"""
$ports = @(22, 80, 443, 3389, 8080, 5050)
foreach ($port in $ports) {{
    try {{
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect('{KALI_IP}', $port)
        Write-Output "Port $port open"
        $tcp.Close()
    }} catch {{
        Write-Output "Port $port closed"
    }}
}}
"""
    subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True, text=True, timeout=15
    )
    log("   Port scan completed")

    filepath = capture_screenshot("port_scan")
    if filepath:
        send_to_kali(filepath, "Port Scan Activity")


def simulate_file_changes():
    """Simulate suspicious file activity"""
    log("🚨 SIMULATING: Suspicious File Activity")
    test_file = "C:\\Windows\\Temp\\suspicious_file.txt"
    with open(test_file, "w") as f:
        f.write("Simulated malicious file content")
    log(f"   Created file: {test_file}")
    time.sleep(1)

    filepath = capture_screenshot("file_activity")
    if filepath:
        send_to_kali(filepath, "Suspicious File Activity")

    # Clean up
    os.remove(test_file)
    log("   Cleaned up suspicious file")


def run_full_simulation():
    print("\n" + "="*60)
    print("  SIEM Attack Simulation - Starting")
    print(f"  Sending screenshots to: {KALI_IP}:{KALI_PORT}")
    print("="*60)
    print("\nSimulating 4 attack scenarios:")
    print("  1. Failed Login Attempts")
    print("  2. Unauthorized User Creation")
    print("  3. Port Scan Activity")
    print("  4. Suspicious File Activity")
    print("\nAll attacks will appear in your SIEM web app!")
    print("="*60 + "\n")
    time.sleep(2)

    print("\n" + "-"*50)
    print("ATTACK 1: Failed Login Attempts")
    print("-"*50)
    simulate_failed_logins()
    time.sleep(3)

    print("\n" + "-"*50)
    print("ATTACK 2: Unauthorized User Creation")
    print("-"*50)
    simulate_user_creation()
    time.sleep(3)

    print("\n" + "-"*50)
    print("ATTACK 3: Port Scan Activity")
    print("-"*50)
    simulate_port_scan()
    time.sleep(3)

    print("\n" + "-"*50)
    print("ATTACK 4: Suspicious File Activity")
    print("-"*50)
    simulate_file_changes()
    time.sleep(2)

    print("\n" + "="*60)
    print("  Simulation Complete!")
    print("  Now check your SIEM web app:")
    print("  - Chat: Ask 'What attacks happened?'")
    print("  - Dashboard: See updated charts")
    print("  - Timeline: See attack timeline")
    print("  - Alert Log: See all new alerts")
    print("="*60 + "\n")


if __name__ == "__main__":
    run_full_simulation()
