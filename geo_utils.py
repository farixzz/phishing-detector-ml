import requests
from urllib.parse import urlparse
from tldextract import extract

def get_geo_from_url(url):
    """
    Resolves a URL to its IP address and then queries for its geolocation.
    Returns (latitude, longitude, country, domain) or None if unsuccessful.
    """
    try:
        # Extract the registered domain to resolve the correct IP (handles subdomains)
        ext = extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        
        # Resolve domain to IP using Google's public DNS
        dns_response = requests.get(
            f"https://dns.google/resolve?name={domain}",
            timeout=5
        ).json()
        
        # Find the first A record (IPv4 address)
        ip_address = next((item["data"] for item in dns_response.get("Answer", []) if item["type"] == 1), None)

        if not ip_address:
            return None

        # Get geolocation from the IP address
        geo_response = requests.get(
            f"http://ip-api.com/json/{ip_address}",
            timeout=5
        ).json()
        
        if geo_response.get("status") == "success":
            return (
                geo_response.get("lat"),
                geo_response.get("lon"),
                geo_response.get("country"),
                domain
            )
            
    except (requests.exceptions.RequestException, KeyError, IndexError):
        # Catch network errors, JSON parsing errors, or if 'Answer' doesn't exist
        pass

    return None