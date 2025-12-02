def enrich_iocs(iocs):
    enrichment = {}
    enrichment["url_reputation"] = {url: "malicious" if "malicious" in url else "unknown" for url in iocs.get("urls", [])}
    enrichment["hash_reputation"] = {h: "blacklisted" for h in iocs.get("hashes", [])}
    enrichment["sender_reputation"] = "suspicious" if "attacker" in iocs.get("sender", "") else "clean"
    return enrichment

if __name__ == "__main__":
    test = {"urls": ["https://malicious.com"], "hashes": ["5d41402abc4b2a76b9719d911017c592"], "sender": "attacker@bad.com"}
    print(enrich_iocs(test))
