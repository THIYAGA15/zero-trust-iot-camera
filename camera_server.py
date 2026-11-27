import cv2
import json
import base64
import smtplib
import logging
from email.message import EmailMessage
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet

app = Flask(__name__)

# 1. Real AES Encryption Engine
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# 2. Zero-Trust Policy & Brute-Force Defense
VALID_TOKEN = "ZT-CAM-LIVE-2026"
failed_attempts = {}
banned_ips = set()
MAX_ATTEMPTS = 3

# 3. Gmail SOC Alert Configuration
SENDER_EMAIL = "nseshoes@gmail.com"
APP_PASSWORD = " yourpassword"
RECEIVER_EMAIL = "nseshoes@gmail.com"

# 4. SIEM Structured JSON Log File
logging.basicConfig(filename="soc_camera_alerts.log", level=logging.INFO, format="%(message)s")

def send_gmail_soc_alert(alert_type, severity, source_ip, details):
    msg = EmailMessage()
    msg['Subject'] = f"[CRITICAL IoT SOC ALERT] {alert_type} from {source_ip}"
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL

    body = f"""
    ====================================================
       ZERO-TRUST IOT CAMERA SECURITY INCIDENT REPORT
    ====================================================
    Device ID : LAPTOP-FRONT-CAM-01
    Alert Type : {alert_type}
    Severity : {severity}
    Attacker IP : {source_ip}
    Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    Details : {details}
    Auto-Action : Attacker IP Quarantined (HTTP 403 Blocked)
    ====================================================
    """
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL('://gmail.com', 465) as smtp:
            smtp.login(SENDER_EMAIL, APP_PASSWORD)
            smtp.send_message(msg)
        print(f"[EMAIL SENT] Real-time SOC Alert delivered to {RECEIVER_EMAIL}!")
    except Exception as e:
        print(f"[EMAIL NOTICE] SMTP Auth failed (Use 16-char Google App Password for live delivery): {e}")

def log_soc_event(event_type, severity, source_ip, details):
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_id": "LAPTOP-FRONT-CAM-01",
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip,
        "details": details
    }
    json_str = json.dumps(log_entry)
    logging.info(json_str)
    print(f"\n[SOC SIEM LOG] {json_str}")

@app.route("/capture", methods=["GET"])
def capture_encrypted_frame():
    client_ip = request.remote_addr
    auth_header = request.headers.get("Authorization")

    # Block Quarantined IPs
    if client_ip in banned_ips:
        log_soc_event("BLOCKED_IP_ACCESS", "CRITICAL", client_ip, "Quarantined attacker attempted stream access")
        return jsonify({"error": "Access Denied: IP Quarantined by Zero-Trust Policy"}), 403

    # Verify Zero-Trust Token
    if auth_header != f"Bearer {VALID_TOKEN}":
        failed_attempts[client_ip] = failed_attempts.get(client_ip, 0) + 1
        attempts = failed_attempts[client_ip]
        log_soc_event("AUTH_FAILURE", "MEDIUM", client_ip, f"Invalid token attempt {attempts}/{MAX_ATTEMPTS}")

        if attempts >= MAX_ATTEMPTS:
            banned_ips.add(client_ip)
            msg = "Brute-Force Threshold Exceeded (3 Failed Attempts) - IP Quarantined!"
            log_soc_event("BRUTE_FORCE_LOCKDOWN", "HIGH", client_ip, msg)
            send_gmail_soc_alert("BRUTE_FORCE_LOCKDOWN", "CRITICAL", client_ip, msg)
            return jsonify({"error": "Brute-Force Detected! IP Banned & SOC Alerted."}), 403

        return jsonify({"error": "Unauthorized Token"}), 401

    # Authorized -> Capture Real Frame from Laptop Front Camera & AES Encrypt
    failed_attempts[client_ip] = 0
    cam = cv2.VideoCapture(0)
    ret, frame = cam.read()
    cam.release()

    if not ret:
        return jsonify({"error": "Front Camera busy or not detected"}), 500

    _, buffer = cv2.imencode('.jpg', frame)
    encrypted_frame = cipher_suite.encrypt(buffer.tobytes())
    encrypted_b64 = base64.b64encode(encrypted_frame).decode('utf-8')

    log_soc_event("AUTHORIZED_ENCRYPTED_FRAME", "INFO", client_ip, "Front camera frame captured & AES encrypted")
    return jsonify({
        "status": "AUTHORIZED",
        "encryption": "AES-CBC-HMAC-SHA256",
        "encrypted_frame_sample": encrypted_b64[:90] + "..."
    }), 200

if __name__ == "__main__":
    print("=== ZERO-TRUST FRONT CAMERA SECURITY SERVER RUNNING ON PORT 5000 ===")
    app.run(host="127.0.0.1", port=5000)