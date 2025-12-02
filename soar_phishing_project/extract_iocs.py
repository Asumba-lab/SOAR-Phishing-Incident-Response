import re

def extract_iocs(email_body, email_headers):
    urls = re.findall(r'https?://[^\s"]+', email_body)
    hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', email_body)
    sender = email_headers.get("From", "Unknown")
    return {"urls": list(set(urls)), "hashes": list(set(hashes)), "sender": sender}

if __name__ == "__main__":
    email_body = "Hello, verify: https://malicious.com"
    email_headers = {"From": "attacker@bad.com"}
    print(extract_iocs(email_body, email_headers))
