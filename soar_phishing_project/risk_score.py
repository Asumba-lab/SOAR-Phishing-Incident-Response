def calculate_risk_score(enrichment):
    score = 0
    if any(v == "malicious" for v in enrichment.get("url_reputation", {}).values()):
        score += 50
    if any(v == "blacklisted" for v in enrichment.get("hash_reputation", {}).values()):
        score += 30
    if enrichment.get("sender_reputation") == "suspicious":
        score += 20
    return score

if __name__ == "__main__":
    sample = {
        "url_reputation": {"a": "malicious"},
        "hash_reputation": {"b": "blacklisted"},
        "sender_reputation": "suspicious"
    }
    print("Risk Score:", calculate_risk_score(sample))
