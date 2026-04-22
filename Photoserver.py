"""
photo_server.py — Intruder Photo Receiver (Run on Kali Linux)
--------------------------------------------------------------
Flask server that receives intruder screenshots from the
Windows endpoint capture.py script and saves them locally.

Usage:
    pip install flask
    python3 photo_server.py

Endpoints:
    POST /upload  — Receive photo from Windows agent
    GET  /photos  — List all captured photos
    GET  /health  — Health check
"""

from flask import Flask, request, jsonify
import os
from datetime import datetime

# =============================================
# Configuration
# =============================================
PHOTO_FOLDER = "/home/kali/conversational-siem/intruder_photos"
PORT         = 5050

os.makedirs(PHOTO_FOLDER, exist_ok=True)

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload_photo():
    """Receive intruder screenshot from Windows agent"""
    try:
        if "photo" not in request.files:
            return jsonify({"error": "No photo in request"}), 400

        photo     = request.files["photo"]
        timestamp = request.form.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        attack    = request.form.get("type", "unknown")

        # Save photo with timestamp
        filename = f"intruder_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        filepath = os.path.join(PHOTO_FOLDER, filename)
        photo.save(filepath)

        print(f"✅ Photo received: {filename}")
        print(f"   Timestamp  : {timestamp}")
        print(f"   Attack Type: {attack}")

        return jsonify({"status": "success", "file": filename}), 200

    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/photos", methods=["GET"])
def list_photos():
    """List all captured intruder photos"""
    try:
        photos = []
        for f in sorted(os.listdir(PHOTO_FOLDER), reverse=True):
            if f.endswith((".jpg", ".png")):
                filepath = os.path.join(PHOTO_FOLDER, f)
                photos.append({
                    "filename":  f,
                    "path":      filepath,
                    "timestamp": f.replace("intruder_", "").replace(".png", "").replace(".jpg", ""),
                    "size":      os.path.getsize(filepath)
                })
        return jsonify({"photos": photos, "total": len(photos)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({"status": "running", "port": PORT}), 200


if __name__ == "__main__":
    print("=" * 50)
    print(f"  Intruder Photo Receiver")
    print(f"  Running on port : {PORT}")
    print(f"  Saving photos to: {PHOTO_FOLDER}")
    print("=" * 50)
    app.run(host="0.0.0.0", port=PORT, debug=False)
