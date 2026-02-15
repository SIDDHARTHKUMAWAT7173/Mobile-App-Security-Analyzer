from utils.owasp import format_owasp

import re


class SecretScanner:

    AWS_PATTERN = r"AKIA[0-9A-Z]{16}"
    GENERIC_API_PATTERN = r"(?i)(api_key|apikey|secret|token)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']"
    BEARER_PATTERN = r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"
    EMAIL_PATTERN = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    CREDENTIAL_PATTERN = r'(?i)(username|user|password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']'

    def __init__(self, analysis):
        self.analysis = analysis

    def scan(self):
        findings = []

        for string_obj in self.analysis.get_strings():
            value = string_obj.get_value()

            # AWS Keys
            if re.search(self.AWS_PATTERN, value):
                findings.append({
                    "type": "Hardcoded Secret",
                    "issue": "Possible hardcoded AWS access key detected",
                    "severity": "Critical",
                    "owasp": format_owasp("M1"),
                    "description": "Hardcoded AWS keys can allow unauthorized access to cloud resources.",
                    "remediation": "Store secrets securely using Android Keystore or backend configuration."
                })

            # Generic API Keys
            if re.search(self.GENERIC_API_PATTERN, value):
                findings.append({
                    "type": "Hardcoded Secret",
                    "issue": "Possible hardcoded API key or secret detected",
                    "severity": "High",
                    "owasp": format_owasp("M1"),
                    "description": "Hardcoded API keys can be extracted from the APK.",
                    "remediation": "Avoid embedding secrets directly in source code."
                })

            # Bearer tokens
            if re.search(self.BEARER_PATTERN, value):
                findings.append({
                    "type": "Hardcoded Token",
                    "issue": "Bearer token detected in application strings",
                    "severity": "High",
                    "owasp": format_owasp("M1"),
                    "description": "Hardcoded bearer tokens may allow unauthorized API access.",
                    "remediation": "Use secure authentication flow and token management."
                })

            # Emails (informational but useful)
            if re.search(self.EMAIL_PATTERN, value):
                findings.append({
                    "type": "Information Disclosure",
                    "issue": "Email address found in application strings",
                    "severity": "Low",
                    "owasp": format_owasp("M6"),
                    "description": "Exposed email addresses may lead to information leakage.",
                    "remediation": "Avoid hardcoding sensitive contact details."
                })
            # Hardcoded credentials
            if re.search(self.CREDENTIAL_PATTERN, value):
                findings.append({
                    "type": "Hardcoded Credentials",
                    "issue": "Possible hardcoded authentication credentials detected",
                    "severity": "High",
                    "owasp": format_owasp("M4"),
                    "description": "Hardcoded usernames or passwords can lead to authentication bypass.",
                    "remediation": "Avoid storing credentials in source code. Use secure authentication mechanisms."
                })

        return findings
