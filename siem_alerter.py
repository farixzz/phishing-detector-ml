import socket
from config import SIEM_IP, SIEM_PORT

def send_cef_alert(url, confidence, verdict):
    """
    Formats a message in Common Event Format (CEF) and sends it
    to the configured SIEM server over UDP.
    """
    # --- CEF Message Formatting ---
    # This is a standard log format that all SIEMs can understand.
    # The format is: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    
    version = "0"
    device_vendor = "PhishingDetector"
    device_product = "MLScanner"
    device_version = "1.0"
    signature_id = "1001" # A unique ID for this type of alert
    name = "Phishing URL Detected"
    severity = "8" # On a scale of 0-10, this is High/Critical

    # The extension contains all the details of the event.
    extension = f"request={url} ml_confidence={confidence:.2f} ml_verdict={verdict}"
    
    cef_message = f"CEF:{version}|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}|{extension}"

    # --- Sending the Alert via UDP Socket ---
    try:
        print(f"📡 Sending CEF alert to {SIEM_IP}:{SIEM_PORT}...")
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Send the message, encoded into bytes
        sock.sendto(cef_message.encode('utf-8'), (SIEM_IP, SIEM_PORT))
        sock.close()
        print("   Alert sent successfully.")
    except Exception as e:
        print(f"   ❌ Error sending SIEM alert: {e}")
