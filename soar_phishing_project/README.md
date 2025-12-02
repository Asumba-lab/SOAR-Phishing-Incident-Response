# SOAR Phishing Incident Response Project

A Python-based SOAR (Security Orchestration, Automation, and Response) solution for automated phishing incident response. This project demonstrates a complete workflow for detecting, analyzing, and responding to phishing attempts through automated playbooks.

## Features

- **IOC Extraction**: Automatically extracts Indicators of Compromise (IOCs) from email content
- **Threat Intelligence Enrichment**: Enhances IOCs with reputation data
- **Risk Scoring**: Calculates a risk score based on multiple factors
- **Automated Response**: Takes action based on risk thresholds
- **Simulation Mode**: Safe testing environment with simulation capabilities

## Project Structure

- `extract_iocs.py`: Extracts IOCs (URLs, hashes, sender info) from email content
- `enrich_iocs.py`: Enhances IOCs with threat intelligence data
- `risk_score.py`: Calculates a risk score based on enriched IOCs
- `isolate_account.py`: Contains account isolation functionality (simulated)
- `playbook_demo.py`: Main demonstration script showing the complete workflow

## How It Works

1. **IOC Extraction**:
   - Extracts URLs, file hashes, and sender information from email content
   - Uses regex patterns to identify potential IOCs

2. **IOC Enrichment**:
   - Checks URLs against known malicious indicators
   - Verifies hashes against threat intelligence
   - Analyzes sender reputation

3. **Risk Scoring**:
   - Malicious URLs: +50 points
   - Blacklisted hashes: +30 points
   - Suspicious sender: +20 points
   - Risk thresholds:
     - ≥ 80: Critical - Automatic account isolation
     - 40-79: Medium - Requires analyst review
     - < 40: Low - Likely benign

4. **Response Actions**:
   - High-risk incidents trigger automatic account isolation
   - Medium-risk incidents are flagged for analyst review
   - Low-risk incidents are logged for monitoring

## Prerequisites

- Python 3.6+
- No external dependencies required (uses standard library only)

## Getting Started

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd soar_phishing_project
   ```

2. Run the demo:
   ```bash
   python playbook_demo.py
   ```

## Customization

- Modify `playbook_demo.py` to use your own email content and headers
- Adjust risk scoring thresholds in `risk_score.py`
- Implement real API calls in `enrich_iocs.py` for production use
- Replace simulation in `isolate_account.py` with actual account isolation logic

## Example Output

```
--- STEP 1: IOC EXTRACTION ---
{'urls': ['https://malicious-link.com'], 'hashes': ['5d41402abc4b2a76b9719d911017c592'], 'sender': 'attacker@malicious.com'}

--- STEP 2: ENRICHMENT ---
{'url_reputation': {'https://malicious-link.com': 'malicious'}, 'hash_reputation': {'5d41402abc4b2a76b9719d911017c592': 'blacklisted'}, 'sender_reputation': 'suspicious'}

--- STEP 3: RISK SCORE ---
Risk Score: 100

--- STEP 4: DECISION ---
[SIMULATION] Account victim@example.com DISABLED.
[SIMULATION] Password reset triggered.
[SIMULATION] MFA enforced.
```

## Security Note

This is a demonstration project. For production use:
- Implement proper error handling
- Add logging
- Secure sensitive data
- Use real threat intelligence feeds
- Follow your organization's security policies
