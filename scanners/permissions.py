from utils.owasp import format_owasp

class PermissionScanner:

    # Some commonly abused or sensitive permissions
    DANGEROUS_PERMISSIONS = {
        "android.permission.READ_SMS": "Access to SMS messages",
        "android.permission.SEND_SMS": "Ability to send SMS messages",
        "android.permission.READ_CONTACTS": "Access to user's contacts",
        "android.permission.RECORD_AUDIO": "Access to microphone",
        "android.permission.ACCESS_FINE_LOCATION": "Precise location access",
        "android.permission.CAMERA": "Access to camera",
        "android.permission.READ_EXTERNAL_STORAGE": "Read external storage",
        "android.permission.WRITE_EXTERNAL_STORAGE": "Write to external storage"
    }

    def __init__(self, apk):
        self.apk = apk

    def scan(self):
        findings = []
        permissions = self.apk.get_permissions()

        for perm in permissions:
            if perm in self.DANGEROUS_PERMISSIONS:
                findings.append({
                    "type": "Permission Risk",
                    "issue": f"Sensitive permission requested: {perm}",
                    "severity": "Medium",
                    "owasp": format_owasp("M8"),
                    "description": self.DANGEROUS_PERMISSIONS[perm],
                    "remediation": "Ensure this permission is strictly required and justified."
                })

        return findings
