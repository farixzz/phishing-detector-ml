import requests
import base64
import streamlit as st

# --- [THE DEFINITIVE FIX] ---
# This function makes the code work BOTH locally and in the cloud.
def get_api_keys():
    """
    Tries to get API keys from Streamlit's secrets manager.
    If it fails (i.e., we are running locally), it falls back to the config.py file.
    """
    try:
        # This will work when the app is deployed on Streamlit Community Cloud
        vt_key = st.secrets["VIRUSTOTAL_API_KEY"]
        gsb_key = st.secrets["GOOGLE_API_KEY"]
    except (KeyError, FileNotFoundError):
        # This will work when you run the app locally (CLI or streamlit run app.py)
        # It imports config.py only when needed, inside the fallback.
        from config import VIRUSTOTAL_API_KEY, GOOGLE_API_KEY
        vt_key = VIRUSTOTAL_API_KEY
        gsb_key = GOOGLE_API_KEY
    return vt_key, gsb_key

# Get the keys once using our smart function
VIRUSTOTAL_API_KEY, GOOGLE_API_KEY = get_api_keys()
# --------------------------------------------------------

def check_google_safe_browsing(url):
    """
    Checks a URL against the Google Safe Browsing (Web Risk) API.
    Returns 'MALICIOUS' if a threat is found, 'SAFE' otherwise, or 'API_ERROR'.
    """
    # Added robustness: check if key is configured
    if not GOOGLE_API_KEY or "YOUR_KEY_HERE" in GOOGLE_API_KEY:
        return "API_ERROR", "Google API Key not configured."
    
    api_url = f"https://webrisk.googleapis.com/v1/uris:search?key={GOOGLE_API_KEY}"
    payload = {
        'uri': url,
        'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE']
    }
    
    try:
        response = requests.get(api_url, params=payload, timeout=5)
        response.raise_for_status()
        result = response.json()
        if 'threat' in result:
            threat_types = [t.replace('_', ' ').title() for t in result['threat']['threatTypes']]
            return "MALICIOUS", f"Google Safe Browsing flagged as: {', '.join(threat_types)}"
        else:
            return "SAFE", "Google Safe Browsing found no threats."
    except requests.exceptions.RequestException:
        return "API_ERROR", "Could not connect to Google API."

def check_virustotal(url):
    """
    Checks a URL against the VirusTotal API v3.
    Returns a summary of the scan results.
    """
    # Added robustness: check if key is configured
    if not VIRUSTOTAL_API_KEY or "YOUR_KEY_HERE" in VIRUSTOTAL_API_KEY:
        return "API_ERROR", "VirusTotal API Key not configured."

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 404:
            return "NOT_FOUND", "URL not found in VirusTotal database."
        response.raise_for_status()
        result = response.json()
        stats = result['data']['attributes']['last_analysis_stats']
        malicious_votes = stats.get('malicious', 0)
        harmless_votes = stats.get('harmless', 0)
        if malicious_votes > 0:
            return "MALICIOUS", f"VirusTotal flagged as malicious by {malicious_votes} vendors."
        else:
            return "SAFE", f"VirusTotal found no threats ({harmless_votes} vendors marked as harmless)."
    except requests.exceptions.RequestException as e:
        # This print is useful for local CLI debugging, so we keep it.
        print(f"Error checking VirusTotal: {e}")
        return "API_ERROR", "Could not connect to VirusTotal API."

# --- Your previous test block is preserved and will work correctly ---
if __name__ == '__main__':
    # This block allows us to test the script directly from the command line
    # It will correctly use the fallback to config.py
    test_malicious_url = "http://malware.testing.google.test/testing/malware/"
    test_safe_url = "https://www.google.com"

    print("--- Testing Google Safe Browsing ---")
    status, reason = check_google_safe_browsing(test_malicious_url)
    print(f"URL: {test_malicious_url} -> Status: {status}, Reason: {reason}")
    status, reason = check_google_safe_browsing(test_safe_url)
    print(f"URL: {test_safe_url} -> Status: {status}, Reason: {reason}\n")
    
    print("--- Testing VirusTotal ---")
    status, reason = check_virustotal(test_safe_url)
    print(f"URL: {test_safe_url} -> Status: {status}, Reason: {reason}")