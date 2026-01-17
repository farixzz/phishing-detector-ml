import re

def normalize_url(url):
    """
    This is the definitive URL normalization function. It removes the scheme (http/https)
    and the 'www.' prefix to create a consistent format for the ML model.
    This is the core of the fix you discovered.
    """
    if not isinstance(url, str):
        return ""
    return re.sub(r'^(https?://)?(www\.)?', '', url).strip('/')
