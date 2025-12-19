from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import hashlib
import logging
from pathlib import Path
import json
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RiskAssessor:
    """
    Risk assessment engine for evaluating the severity of identified threats.
    Uses a rule-based system with configurable weights and thresholds.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the risk assessor with configuration."""
        self.config = config
        self.rules = self._load_rules()
        self.risk_weights = {
            'critical': 1.0,
            'high': 0.75,
            'medium': 0.5,
            'low': 0.25,
            'info': 0.1
        }
        
    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load risk assessment rules from configuration or default rules."""
        # Default rules if none provided in config
        default_rules = [
            {
                'id': 'malicious_url',
                'name': 'Malicious URL Detected',
                'description': 'URL identified as malicious by threat intelligence',
                'condition': "ioc.get('type') == 'url' and ioc.get('malicious') is True",
                'severity': 'critical',
                'weight': 1.0,
                'mitigation': 'Block URL and investigate source',
                'enabled': True
            },
            {
                'id': 'malicious_domain',
                'name': 'Malicious Domain Detected',
                'description': 'Domain identified as malicious by threat intelligence',
                'condition': "ioc.get('type') == 'domain' and ioc.get('malicious') is True",
                'severity': 'high',
                'weight': 0.8,
                'mitigation': 'Block domain and investigate further',
                'enabled': True
            },
            {
                'id': 'suspicious_attachment',
                'name': 'Suspicious Attachment Detected',
                'description': 'Attachment with suspicious characteristics detected',
                'condition': "ioc.get('type') == 'attachment' and ioc.get('suspicious') is True",
                'severity': 'high',
                'weight': 0.9,
                'mitigation': 'Quarantine attachment and scan for malware',
                'enabled': True
            },
            {
                'id': 'credential_phishing',
                'name': 'Credential Phishing Attempt',
                'description': 'Email contains links to potential credential phishing sites',
                'condition': "any('login' in url or 'signin' in url or 'account' in url for url in ioc.get('urls', []) if isinstance(url, str)) and ioc.get('type') == 'email'",
                'severity': 'high',
                'weight': 0.85,
                'mitigation': 'Warn users and block access to phishing sites',
                'enabled': True
            },
            {
                'id': 'suspicious_sender',
                'name': 'Suspicious Sender',
                'description': 'Email from suspicious or unknown sender',
                'condition': "ioc.get('type') == 'email' and ioc.get('suspicious_sender') is True",
                'severity': 'medium',
                'weight': 0.6,
                'mitigation': 'Flag for review and consider blocking sender',
                'enabled': True
            },
            {
                'id': 'url_shortener',
                'name': 'URL Shortener Detected',
                'description': 'Email contains shortened URLs which may hide malicious links',
                'condition': "any(domain in ['bit.ly', 'tinyurl.com', 'goo.gl'] for domain in ioc.get('domains', [])) and ioc.get('type') == 'email'",
                'severity': 'medium',
                'weight': 0.5,
                'mitigation': 'Inspect the full URL before allowing access',
                'enabled': True
            },
            {
                'id': 'unusual_attachment_type',
                'name': 'Unusual Attachment Type',
                'description': 'Email contains unusual or potentially dangerous attachment types',
                'condition': "any(ext in ['.exe', '.js', '.vbs', '.ps1', '.bat', '.cmd', '.scr', '.pif'] for ext in ioc.get('attachment_types', [])) and ioc.get('type') == 'email'",
                'severity': 'high',
                'weight': 0.8,
                'mitigation': 'Block and scan attachment before delivery',
                'enabled': True
            },
            {
                'id': 'recently_registered_domain',
                'name': 'Recently Registered Domain',
                'description': 'Email contains links to recently registered domains',
                'condition': "ioc.get('domain_age_days', 9999) < 30 and ioc.get('type') in ['url', 'domain']",
                'severity': 'medium',
                'weight': 0.6,
                'mitigation': 'Investigate domain and consider blocking if suspicious',
                'enabled': True
            }
        ]
        
        # Load custom rules from config if available
        custom_rules = self.config.get('risk_rules', [])
        return custom_rules if custom_rules else default_rules
    
    def assess_ioc(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess the risk of a single Indicator of Compromise (IOC).
        
        Args:
            ioc: Dictionary containing IOC details
            
        Returns:
            Dict containing risk assessment results
        """
        assessment = {
            'ioc_id': ioc.get('id', hashlib.sha256(str(ioc).encode()).hexdigest()[:16]),
            'type': ioc.get('type', 'unknown'),
            'value': ioc.get('value', 'unknown'),
            'risks': [],
            'risk_score': 0,
            'severity': 'info',
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': {}
        }
        
        # Evaluate each rule
        for rule in self.rules:
            if not rule.get('enabled', True):
                continue
                
            try:
                # Evaluate the rule condition in a safe way
                condition_met = eval(rule['condition'], {'ioc': ioc, 'any': any, 'all': all})
                if condition_met:
                    risk = {
                        'rule_id': rule['id'],
                        'rule_name': rule['name'],
                        'description': rule['description'],
                        'severity': rule['severity'],
                        'weight': rule.get('weight', 0.5),
                        'mitigation': rule.get('mitigation', ''),
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    assessment['risks'].append(risk)
                    
                    # Update overall risk score
                    severity_weight = self.risk_weights.get(rule['severity'].lower(), 0.1)
                    assessment['risk_score'] += severity_weight * rule.get('weight', 0.5)
                    
                    # Update overall severity if this is higher
                    current_severity = self.risk_weights.get(assessment['severity'].lower(), 0)
                    new_severity = self.risk_weights.get(rule['severity'].lower(), 0)
                    if new_severity > current_severity:
                        assessment['severity'] = rule['severity']
                        
            except Exception as e:
                logger.warning(f"Error evaluating rule {rule.get('id')}: {e}")
        
        # Cap risk score at 10
        assessment['risk_score'] = min(10, assessment['risk_score'])
        
        # If no risks found but we have a suspicious IOC, set a baseline risk
        if not assessment['risks'] and ioc.get('malicious'):
            assessment['risk_score'] = 5.0
            assessment['severity'] = 'medium'
            assessment['risks'].append({
                'rule_id': 'default_malicious',
                'rule_name': 'Malicious Indicator',
                'description': 'Indicator was flagged as malicious but no specific risk rule matched',
                'severity': 'medium',
                'weight': 0.5,
                'mitigation': 'Investigate and take appropriate action',
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return assessment
    
    def assess_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess the risk of an email message and its components.
        
        Args:
            email_data: Dictionary containing email data and extracted IOCs
            
        Returns:
            Dict containing risk assessment results for the email
        """
        assessment = {
            'email_id': email_data.get('message_id', hashlib.sha256(str(email_data).encode()).hexdigest()[:16]),
            'timestamp': datetime.utcnow().isoformat(),
            'subject': email_data.get('subject', 'No Subject'),
            'from': email_data.get('from', 'unknown@example.com'),
            'to': email_data.get('to', []),
            'ioc_assessments': [],
            'risks': [],
            'risk_score': 0,
            'severity': 'info',
            'recommended_actions': []
        }
        
        # Assess each IOC in the email
        for ioc in email_data.get('iocs', []):
            ioc_assessment = self.assess_ioc(ioc)
            assessment['ioc_assessments'].append(ioc_assessment)
            
            # Update overall risk score and severity
            assessment['risk_score'] += ioc_assessment['risk_score']
            
            # Update overall severity if this is higher
            current_severity = self.risk_weights.get(assessment['severity'].lower(), 0)
            new_severity = self.risk_weights.get(ioc_assessment['severity'].lower(), 0)
            if new_severity > current_severity:
                assessment['severity'] = ioc_assessment['severity']
            
            # Add any risks to the main assessment
            assessment['risks'].extend(ioc_assessment['risks'])
        
        # Cap risk score at 10
        assessment['risk_score'] = min(10, assessment['risk_score'])
        
        # Determine recommended actions based on risk level
        self._determine_actions(assessment)
        
        return assessment
    
    def _determine_actions(self, assessment: Dict[str, Any]):
        """Determine recommended actions based on risk assessment."""
        risk_score = assessment['risk_score']
        
        # Reset recommended actions
        assessment['recommended_actions'] = []
        
        # Critical risk actions
        if risk_score >= 8.0:
            assessment['recommended_actions'].extend([
                'Immediately isolate affected systems',
                'Reset credentials for affected accounts',
                'Block all identified IOCs at the network perimeter',
                'Initiate incident response procedures',
                'Notify security team and management'
            ])
        # High risk actions
        elif risk_score >= 6.0:
            assessment['recommended_actions'].extend([
                'Block malicious IOCs',
                'Quarantine suspicious emails',
                'Scan affected systems for compromise',
                'Notify security team',
                'Consider resetting credentials for affected accounts'
            ])
        # Medium risk actions
        elif risk_score >= 4.0:
            assessment['recommended_actions'].extend([
                'Flag email for review',
                'Monitor for similar activity',
                'Consider blocking suspicious URLs or domains',
                'Educate users about potential threats'
            ])
        # Low risk actions
        elif risk_score >= 2.0:
            assessment['recommended_actions'].extend([
                'Log the event for future reference',
                'Monitor for similar activity',
                'Consider user awareness training'
            ])
        # Info or very low risk
        else:
            assessment['recommended_actions'].append('No action required, log for reference')
        
        # Add any specific mitigations from triggered rules
        for risk in assessment['risks']:
            if 'mitigation' in risk and risk['mitigation']:
                if risk['mitigation'] not in assessment['recommended_actions']:
                    assessment['recommended_actions'].append(risk['mitigation'])
    
    def generate_report(self, assessment: Dict[str, Any], format: str = 'text') -> str:
        """
        Generate a human-readable report of the risk assessment.
        
        Args:
            assessment: Risk assessment results
            format: Output format ('text' or 'json')
            
        Returns:
            Formatted report as a string
        """
        if format.lower() == 'json':
            import json
            return json.dumps(assessment, indent=2)
            
        # Default to text format
        report = []
        report.append("=" * 80)
        report.append(f"RISK ASSESSMENT REPORT")
        report.append("=" * 80)
        report.append(f"Email ID: {assessment.get('email_id', 'N/A')}")
        report.append(f"Subject: {assessment.get('subject', 'N/A')}")
        report.append(f"From: {assessment.get('from', 'N/A')}")
        report.append(f"To: {', '.join(assessment.get('to', ['N/A']))}")
        report.append(f"Timestamp: {assessment.get('timestamp', 'N/A')}")
        report.append(f"Overall Risk Score: {assessment.get('risk_score', 0):.1f}/10")
        report.append(f"Severity: {assessment.get('severity', 'unknown').upper()}")
        
        report.append("\n" + "-" * 80)
        report.append("DETECTED RISKS")
        report.append("-" * 80)
        
        if not assessment.get('risks'):
            report.append("No significant risks detected.")
        else:
            for i, risk in enumerate(assessment['risks'], 1):
                report.append(f"{i}. [{risk['severity'].upper()}] {risk['rule_name']}")
                report.append(f"   Description: {risk['description']}")
                report.append(f"   Mitigation: {risk.get('mitigation', 'N/A')}")
                report.append(f"   Rule Weight: {risk.get('weight', 0.5):.2f}")
        
        report.append("\n" + "-" * 80)
        report.append("RECOMMENDED ACTIONS")
        report.append("-" * 80)
        
        if not assessment.get('recommended_actions'):
            report.append("No specific actions recommended.")
        else:
            for i, action in enumerate(assessment['recommended_actions'], 1):
                report.append(f"{i}. {action}")
        
        report.append("\n" + "=" * 80)
        return "\n".join(report)

# Example usage
if __name__ == "__main__":
    # Example configuration
    config = {
        'risk_rules': []  # Use default rules
    }
    
    # Create a risk assessor
    assessor = RiskAssessor(config)
    
    # Example IOC assessment
    example_ioc = {
        'type': 'url',
        'value': 'http://malicious-site.com/phish',
        'malicious': True,
        'source': 'VirusTotal',
        'urls': ['http://malicious-site.com/phish'],
        'domains': ['malicious-site.com']
    }
    
    # Assess the IOC
    result = assessor.assess_ioc(example_ioc)
    print(f"IOC Assessment: {json.dumps(result, indent=2)}")
    
    # Example email assessment
    example_email = {
        'message_id': 'example123',
        'subject': 'Urgent: Verify your account now!',
        'from': 'attacker@example.com',
        'to': ['victim@example.com'],
        'iocs': [
            {
                'type': 'url',
                'value': 'http://phishy-site.com/login',
                'malicious': True,
                'urls': ['http://phishy-site.com/login'],
                'domains': ['phishy-site.com']
            },
            {
                'type': 'attachment',
                'value': 'document.pdf.exe',
                'suspicious': True,
                'file_type': 'exe',
                'file_name': 'document.pdf.exe'
            }
        ]
    }
    
    # Assess the email
    email_assessment = assessor.assess_email(example_email)
    print("\nEmail Risk Assessment:")
    print(assessor.generate_report(email_assessment))
