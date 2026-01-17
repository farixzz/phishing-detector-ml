import re
from urllib.parse import urlparse

def get_red_flags(url):
    """
    Analyzes a URL for common, easy-to-understand phishing red flags.
    Returns a list of human-readable warnings.
    """
    flags = []
    
    # Red Flag 1: Use of an IP Address instead of a domain name
    if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', urlparse(url).netloc):
        flags.append("🚨 **IP Address in Domain:** Legitimate sites rarely use a raw IP address.")
        
    # Red Flag 2: Presence of suspicious keywords
    suspicious_keywords = ['secure', 'login', 'verify', 'account', 'update', 'password', 'signin', 'banking']
    if any(keyword in url.lower() for keyword in suspicious_keywords):
        flags.append("⚠️ **Suspicious Keywords:** Contains words often used in phishing attacks (e.g., 'login', 'secure').")
        
    # Red Flag 3: Unusually long URL
    if len(url) > 75:
        flags.append("📏 **Unusually Long URL:** Phishing URLs are often long and complex to hide their true nature.")
        
    # Red Flag 4: Multiple subdomains (e.g., login.facebook.com.some-bad-site.com)
    if urlparse(url).netloc.count('.') > 2:
        flags.append("🌐 **Multiple Subdomains:** Often used to impersonate legitimate services.")
        
    # Red Flag 5: Use of the '@' symbol in the URL
    if '@' in url:
        flags.append("📧 **'@' Symbol in URL:** Can be a trick to obscure the actual domain name.")
        
    return flags