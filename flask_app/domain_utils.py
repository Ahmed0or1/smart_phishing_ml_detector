import re
from urllib.parse import urlparse

def extract_domain(url):
    """
    Extract the primary domain from a given URL.
    For example: 'http://sub.example.com/path' -> 'example.com'
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return None
    except Exception:
        return None

def is_malicious_command(input_text):
    """
    Detect if the input text contains potentially malicious commands.
    """
    malicious_patterns = [
        r";", r"\|", r"&", r"`", r"'", r"\"", r"\$\(", r"\{\{", r"\$\{", r"\.\.",
        r"\/etc\/passwd", r"wget\s", r"curl\s", r"bash\s", r"rm\s+-rf\s",
        r"sudo\s", r"cat\s+/", r"ssh\s", r"scp\s", r"mkfs\s"
    ]
    for pattern in malicious_patterns:
        if re.search(pattern, input_text, re.IGNORECASE):
            return True
    return False

