"""
SecureMed Receiver Service Launcher
Starts the receiver and monitoring dashboard on all interfaces (0.0.0.0:8000)
so mobile phones on the same Wi-Fi network can connect directly.
"""

import sys
import os
import socket

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import uvicorn


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


if __name__ == "__main__":
    local_ip = get_local_ip()
    port = int(os.environ.get("PORT", 8000))
    print("=" * 72)
    print("  [+] SECUREMED: MEDICAL CRYPTOGRAPHIC RECEIVER & RESEARCH DASHBOARD")
    print("=" * 72)
    print(f"[*] Laptop Dashboard URL: http://localhost:{port}")
    print(f"[*] QR URL:               http://{local_ip}:{port}/phone")
    print("=" * 72)
    print("[*] INSTRUCTIONS FOR PHONE:")
    print("  1. Connect your phone to the SAME Wi-Fi network as this laptop.")
    print(f"  2. Open your phone's browser and go to: http://{local_ip}:{port}/phone")
    print("     (Or open the laptop dashboard and scan the QR code with your camera!)")
    print("  3. Pick a device (Pacemaker, ICD, CGM, ECG) and tap 'START TELEMETRY STREAM'.")
    print("=" * 72)

    uvicorn.run("receiver.receiver_service:app", host="0.0.0.0", port=port, log_level="info")
