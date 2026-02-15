import re
from utils.owasp import format_owasp

class CryptoScanner:

    INSECURE_TLS_PATTERNS = [
        r'TrustAllCerts',
        r'X509TrustManager',
        r'HostnameVerifier',
        r'setHostnameVerifier',
        r'checkServerTrusted'
    ]

    def __init__(self, analysis):
        self.analysis = analysis
    


    def scan(self):
        findings = []

        # Iterate through all strings found in DEX
        for string_obj in self.analysis.get_strings():
            value = string_obj.get_value()

            # Insecure TLS / Certificate validation detection
        for pattern in self.INSECURE_TLS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                findings.append({
                    "type": "Insecure TLS Configuration",
                    "issue": "Possible certificate validation bypass detected",
                    "severity": "High",
                    "owasp": format_owasp("M9"),
                    "description": "Application may be bypassing SSL certificate validation, enabling man-in-the-middle attacks.",
                    "remediation": "Ensure proper certificate validation and avoid trusting all certificates."
                })
                break


            # Weak hashing detection
            if re.search(r'MessageDigest\.getInstance\(["\']MD5["\']\)', value):
                findings.append({
                    "type": "Weak Cryptography",
                    "issue": "MD5 hashing detected",
                    "severity": "High",
                    "owasp": format_owasp("M10"),
                    "description": "MD5 is a broken hashing algorithm vulnerable to collisions.",
                    "remediation": "Use SHA-256 or a stronger hashing algorithm."
                })

            # Insecure random usage
            if re.search(r'new\s+Random\(\)', value):
                findings.append({
                    "type": "Weak Random Generator",
                    "issue": "Insecure use of java.util.Random detected",
                    "severity": "Medium",
                    "owasp": format_owasp("M10"),
                    "description": "java.util.Random is predictable and not suitable for cryptographic purposes.",
                    "remediation": "Use java.security.SecureRandom for cryptographic operations."
                })
    

            if re.search(r'MessageDigest\.getInstance\(["\']SHA-?1["\']\)', value):
                findings.append({
                    "type": "Weak Cryptography",
                    "issue": "SHA1 hashing detected",
                    "severity": "Medium",
                    "owasp": format_owasp("M10"),
                    "description": "SHA1 is considered weak and vulnerable to collision attacks.",
                    "remediation": "Use SHA-256 or SHA-3 instead."
                })

            # Weak encryption mode
            if re.search(r'Cipher\.getInstance\(["\']AES/ECB', value):
                findings.append({
                    "type": "Weak Encryption Mode",
                    "issue": "AES in ECB mode detected",
                    "severity": "High",
                    "owasp": format_owasp("M10"),
                    "description": "AES in ECB mode is insecure and reveals data patterns.",
                    "remediation": "Use AES with CBC or GCM mode."
                })

            # -----------------------------------------
            # WebView Security Checks
            # -----------------------------------------

            # Dangerous JavaScript enabled
            if re.search(r'setJavaScriptEnabled\s*\(\s*true\s*\)', value):
                findings.append({
                    "type": "WebView Misconfiguration",
                    "issue": "JavaScript enabled in WebView",
                    "severity": "Medium",
                    "owasp": format_owasp("M7"),
                    "description": "Enabling JavaScript in WebView may expose app to XSS and injection risks.",
                    "remediation": "Disable JavaScript unless strictly required."
                })

            # Allow file access
            if re.search(r'setAllowFileAccess\s*\(\s*true\s*\)', value):
                findings.append({
                    "type": "WebView Misconfiguration",
                    "issue": "WebView allows file access",
                    "severity": "High",
                    "owasp": format_owasp("M2"),
                    "description": "Allowing file access in WebView can expose sensitive local files.",
                    "remediation": "Disable file access in WebView settings."
                })

            # JavaScript interface
            if re.search(r'addJavascriptInterface', value):
                findings.append({
                    "type": "WebView Risk",
                    "issue": "JavaScript interface exposed to WebView",
                    "severity": "High",
                    "owasp": format_owasp("M1"),
                    "description": "Exposing JavaScript interfaces can allow code execution via malicious scripts.",
                    "remediation": "Avoid exposing sensitive methods via addJavascriptInterface."
                })

            # -----------------------------------------
            # Network Security Configuration Checks
            # -----------------------------------------

            # networkSecurityConfig usage
            if re.search(r'networkSecurityConfig', value):
                findings.append({
                    "type": "Network Security Configuration",
                    "issue": "Custom network security configuration detected",
                    "severity": "Medium",
                    "owasp": format_owasp("M3"),
                    "description": "Application uses custom network security configuration. Misconfiguration may weaken SSL protections.",
                    "remediation": "Ensure network security config enforces strong certificate validation."
                })

            # TrustManager implementation
            if re.search(r'TrustManager', value):
                findings.append({
                    "type": "Insecure TrustManager",
                    "issue": "Custom TrustManager detected",
                    "severity": "High",
                    "owasp": format_owasp("M3"),
                    "description": "Custom TrustManager implementations may bypass certificate validation.",
                    "remediation": "Ensure TrustManager validates certificate chains properly."
                })

            # Certificate pinning bypass indicators
            if re.search(r'checkServerTrusted', value):
                findings.append({
                    "type": "Certificate Validation Risk",
                    "issue": "Possible custom certificate validation logic",
                    "severity": "High",
                    "owasp": format_owasp("M3"),
                    "description": "Improper certificate validation may allow MITM attacks.",
                    "remediation": "Implement strict certificate validation and certificate pinning."
                })

            # -----------------------------------------
            # Root / Debug / Emulator Detection
            # -----------------------------------------

            # Root detection indicators
            if re.search(r'su\b', value) or re.search(r'Superuser', value):
                findings.append({
                    "type": "Root Detection Logic",
                    "issue": "Application checks for rooted device",
                    "severity": "Low",
                    "owasp": format_owasp("M7"),
                    "description": "Root detection logic found. May indicate protection mechanisms.",
                    "remediation": "Ensure root detection cannot be bypassed easily."
                })

            # Debug detection
            if re.search(r'isDebuggerConnected', value):
                findings.append({
                    "type": "Anti-Debug Mechanism",
                    "issue": "Debugger detection logic found",
                    "severity": "Low",
                    "owasp": format_owasp("M7"),
                    "description": "Application checks if debugger is attached.",
                    "remediation": "Ensure anti-debug logic is enforced in production builds."
                })

            # Emulator detection
            if re.search(r'generic_x86|goldfish|sdk_gphone', value):
                findings.append({
                    "type": "Emulator Detection",
                    "issue": "Application checks for emulator environment",
                    "severity": "Low",
                    "owasp": format_owasp("M7"),
                    "description": "Emulator detection logic found.",
                    "remediation": "Combine multiple detection methods for stronger protection."
                })

            # Anti-tampering / signature check
            if re.search(r'getPackageInfo|signatures', value):
                findings.append({
                    "type": "Signature Verification",
                    "issue": "Application checks its own signature",
                    "severity": "Low",
                    "owasp": format_owasp("M8"),
                    "description": "Signature verification logic found.",
                    "remediation": "Ensure signature checks are not easily bypassed."
                })

                

        return findings
