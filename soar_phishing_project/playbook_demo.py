from extract_iocs import extract_iocs
from enrich_iocs import enrich_iocs
from risk_score import calculate_risk_score
from isolate_account import isolate_account

email_body = """
Click here to verify: https://malicious-link.com
Hash: 5d41402abc4b2a76b9719d911017c592
"""

email_headers = {"From": "attacker@malicious.com"}

print("\n--- STEP 1: IOC EXTRACTION ---")
iocs = extract_iocs(email_body, email_headers)
print(iocs)

print("\n--- STEP 2: ENRICHMENT ---")
enriched = enrich_iocs(iocs)
print(enriched)

print("\n--- STEP 3: RISK SCORE ---")
score = calculate_risk_score(enriched)
print("Risk Score:", score)

print("\n--- STEP 4: DECISION ---")
if score >= 80:
    isolate_account("victim@example.com")
elif score >= 40:
    print("Medium risk — analyst review required.")
else:
    print("Low risk — benign.")
