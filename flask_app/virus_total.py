import os
import requests

# Retrieve the API key from environment variable.
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_VIRUSTOTAL_API_KEY")

def check_virustotal(domain):
    """
    Check the reputation of a domain using the VirusTotal API.
    
    Parameters:
        domain (str): The domain to query.
    
    Returns:
        dict: The JSON response from VirusTotal or an error dictionary.
    """
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": "74b9f85837b5e37edc2fce8bb989a125acfd6872eec329b85fecfe455ba7a8d6"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses
        return response.json()
    except requests.RequestException as e:
        return {"error": str(e)}

if __name__ == "__main__":
    test_domain = "exploit-db.com"
    print(f"VirusTotal result for {test_domain}:")
    result = check_virustotal(test_domain)
    print(result)
