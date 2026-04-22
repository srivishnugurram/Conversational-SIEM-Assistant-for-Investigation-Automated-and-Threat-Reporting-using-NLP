"""
capture.py — Intruder Detection Script (Run on Windows Endpoint)
----------------------------------------------------------------
Monitors Windows Security Event Log for failed login attempts (Event ID 4625)
Captures a screenshot when detected and sends it to the SIEM server on Kali.

Setup:
    pip install Pillow requests
    python capture.py
"""

import os
import time
import subprocess
import requests
from datetime import datetime

# =============================================
# 🔧 CONFIGURATION
# Update these values before running
# =============================================
try:
    from config import KALI_IP, KALI_PORT, SAVE_FOLDER
except ImportError:
    KALI_IP     = "your_kali_ip_address"    # Run 'ip a' on Kali to find this
    KALI_PORT   = "5050"
    SAVE_FOLDER = "C:\\intruder_photos"

os.makedirs(SAVE_FOLDER, exist_ok=True)


def capture_screenshot():
    """Capture screenshot using PowerShell"""
    try:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 📸 Capturing screenshot...")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = f"intruder_{timestamp}.png"
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

        if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
            size = os.path.getsize(filepath)
            print(f"✅ Screenshot saved: {filepath} ({size} bytes)")
            return filepath
        else:
            print("❌ Screenshot file not created!")
            return None

    except Exception as e:
        print(f"❌ Screenshot error: {e}")
        return None


def send_to_kali(filepath):
    """Send screenshot to Kali SIEM server"""
    try:
        url = f"http://{KALI_IP}:{KALI_PORT}/upload"
        with open(filepath, "rb") as f:
            files = {"photo": (os.path.basename(filepath), f, "image/png")}
            data  = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type":      "screenshot"
            }
            response = requests.post(url, files=files, data=data, timeout=10)

        if response.status_code == 200:
            print(f"✅ Screenshot sent to SIEM server!")
        else:
            print(f"⚠️ Server responded: {response.status_code}")

    except Exception as e:
        print(f"⚠️ Could not send to Kali (saved locally): {e}")


def get_failed_login_count():
    """Get total count of failed login events from Windows Security log"""
    try:
        cmd = [
            "wevtutil", "qe", "Security",
            "/q:*[System[EventID=4625]]",
            "/c:100", "/rd:true", "/f:text"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout.count("4625")
    except Exception as e:
        print(f"Error checking logs: {e}")
        return 0


def get_latest_event_time():
    """Get timestamp of latest failed login event"""
    try:
        cmd = [
            "wevtutil", "qe", "Security",
            "/q:*[System[EventID=4625]]",
            "/c:1", "/rd:true", "/f:text"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        for line in result.stdout.splitlines():
            if "Date:" in line:
                return line.strip()
        return ""
    except:
        return ""


def monitor_failed_logins():
    print("=" * 55)
    print("  Intruder Capture System - Starting...")
    print(f"  Mode: PowerShell Screenshot")
    print(f"  Saving to: {SAVE_FOLDER}")
    print(f"  Sending to SIEM: {KALI_IP}:{KALI_PORT}")
    print("=" * 55)

    last_count      = get_failed_login_count()
    last_event_time = get_latest_event_time()

    print(f"\n📊 Current failed login count: {last_count}")
    print(f"👁️  Watching for NEW failed logins... (Ctrl+C to stop)\n")

    while True:
        try:
            current_count      = get_failed_login_count()
            current_event_time = get_latest_event_time()

            if current_count > last_count or (
                current_event_time and current_event_time != last_event_time
            ):
                new_attempts = current_count - last_count
                print(f"\n{'='*50}")
                print(f"🚨 FAILED LOGIN DETECTED at {datetime.now().strftime('%H:%M:%S')}!")
                print(f"   New attempts: {new_attempts}")
                print(f"{'='*50}")

                last_count      = current_count
                last_event_time = current_event_time

                filepath = capture_screenshot()
                if filepath:
                    send_to_kali(filepath)

                print(f"\n👁️  Continuing to watch...\n")

            else:
                if int(time.time()) % 30 == 0:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring... (failed logins: {current_count})")

            time.sleep(3)

        except KeyboardInterrupt:
            print("\n\n⛔ Monitoring stopped.")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)


if __name__ == "__main__":
    monitor_failed_logins()
