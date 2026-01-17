import requests
import json
import base64
from config import GOOGLE_API_KEY, VIRUSTOTAL_API_KEY

def check_google_safe_browsing(url):
    """
    Checks a URL against the Google Safe Browsing (Web Risk) API.
    Returns 'MALICIOUS' if a threat is found, 'SAFE' otherwise, or 'API_ERROR'.
    """
    api_url = f"https://webrisk.googleapis.com/v1/uris:search?key={GOOGLE_API_KEY}"
    payload = {
        'uri': url,
        'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE']
    }
    
    try:
        response = requests.get(api_url, params=payload)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        
        result = response.json()
        
        # If the 'threat' key exists, it means a threat was found
        if 'threat' in result:
            threat_types = [t.replace('_', ' ').title() for t in result['threat']['threatTypes']]
            return "MALICIOUS", f"Google Safe Browsing flagged as: {', '.join(threat_types)}"
        else:
            return "SAFE", "Google Safe Browsing found no threats."

    except requests.exceptions.RequestException as e:
        #print(f"Error checking Google Safe Browsing: {e}")
        return "API_ERROR", "Could not connect to Google API."
    except Exception as e:
        #print(f"An unexpected error occurred with Google API: {e}")
        return "API_ERROR", "An unexpected error occurred."


def check_virustotal(url):
    """
    Checks a URL against the VirusTotal API v3.
    Returns a summary of the scan results.
    """
    # VirusTotal API v3 requires the URL to be base64 encoded without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(api_url, headers=headers)

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
        print(f"Error checking VirusTotal: {e}")
        return "API_ERROR", "Could not connect to VirusTotal API."
    except Exception as e:
        print(f"An unexpected error occurred with VirusTotal API: {e}")
        return "API_ERROR", "An unexpected error occurred."

if __name__ == '__main__':
    # This block allows us to test the script directly
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
