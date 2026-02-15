from utils.owasp import format_owasp

class ManifestScanner:

    def __init__(self, apk):
        self.apk = apk

    def scan(self):
        findings = []
        manifest = self.apk.get_android_manifest_xml()
        # Check if app is debuggable
        debuggable = self.apk.get_attribute_value("application", "debuggable")
        if debuggable == "true":
            findings.append({
                "type": "Manifest Misconfiguration",
                "issue": "Application is debuggable",
                "severity": "High",
                "owasp": format_owasp("M7"),
                "description": "Debuggable apps allow attackers to attach debuggers and inspect runtime behavior.",
                "remediation": "Disable debuggable flag in production builds."
            })

        # Check if backup is allowed
        allow_backup = self.apk.get_attribute_value("application", "allowBackup")
        if allow_backup == "true":
            findings.append({
                "type": "Data Exposure Risk",
                "issue": "Application allows backup",
                "severity": "Medium",
                "owasp": format_owasp("M2"),
                "description": "Allowing backups may expose sensitive application data.",
                "remediation": "Set android:allowBackup to false for sensitive applications."
            })

        # Check for cleartext traffic
        cleartext = self.apk.get_attribute_value("application", "usesCleartextTraffic")
        if cleartext == "true":
            findings.append({
                "type": "Network Security Issue",
                "issue": "Cleartext traffic allowed",
                "severity": "High",
                "owasp": format_owasp("M3"),
                "description": "Cleartext traffic allows data transmission over HTTP, exposing sensitive data.",
                "remediation": "Enforce HTTPS and disable cleartext traffic."
            })

        # Check exported activities without protection
        activities = self.apk.get_activities()
        for activity in activities:
            exported = self.apk.get_attribute_value("activity", "exported", name=activity)
            if exported == "true":
                findings.append({
                    "type": "Component Exposure",
                    "issue": f"Exported activity detected: {activity}",
                    "severity": "Medium",
                    "owasp": format_owasp("M8"),
                    "description": "Exported components can be accessed by other applications.",
                    "remediation": "Restrict exported components or apply proper permissions."
                })

        uses_cleartext = manifest.get("android:usesCleartextTraffic")

        if uses_cleartext == "true":
            findings.append({
                "type": "Cleartext Traffic Allowed",
                "issue": "Application allows HTTP cleartext traffic",
                "severity": "High",
                "owasp": format_owasp("M3"),
                "description": "Allowing cleartext traffic exposes network communication to interception.",
                "remediation": "Disable cleartext traffic and enforce HTTPS connections."
            })    
            
        # -----------------------------------------
        # Exported Services Check
        # -----------------------------------------
        services = self.apk.get_services()
        for service in services:
            exported = self.apk.get_attribute_value("service", "exported", name=service)
            permission = self.apk.get_attribute_value("service", "permission", name=service)

            if exported == "true" and not permission:
                findings.append({
                    "type": "Component Exposure",
                    "issue": f"Exported service detected without permission: {service}",
                    "severity": "High",
                    "owasp": format_owasp("M8"),
                    "description": "Exported services without permission protection can be accessed by malicious apps.",
                    "remediation": "Restrict exported services or apply proper permission protection."
                })


        # -----------------------------------------
        # Exported Broadcast Receivers Check
        # -----------------------------------------
        receivers = self.apk.get_receivers()
        for receiver in receivers:
            exported = self.apk.get_attribute_value("receiver", "exported", name=receiver)
            permission = self.apk.get_attribute_value("receiver", "permission", name=receiver)

            if exported == "true" and not permission:
                findings.append({
                    "type": "Component Exposure",
                    "issue": f"Exported broadcast receiver detected without permission: {receiver}",
                    "severity": "Medium",
                    "owasp": format_owasp("M8"),
                    "description": "Unprotected broadcast receivers can allow intent injection attacks.",
                    "remediation": "Set proper permissions or disable exported flag."
                })


        # -----------------------------------------
        # Exported Content Providers Check
        # -----------------------------------------
        providers = self.apk.get_providers()
        for provider in providers:
            exported = self.apk.get_attribute_value("provider", "exported", name=provider)
            permission = self.apk.get_attribute_value("provider", "readPermission", name=provider)

            if exported == "true" and not permission:
                findings.append({
                    "type": "Component Exposure",
                    "issue": f"Exported content provider detected without permission: {provider}",
                    "severity": "High",
                    "owasp": format_owasp("M2"),
                    "description": "Unprotected content providers may expose sensitive application data.",
                    "remediation": "Protect content providers with permissions or disable exported."
                })
        

        return findings
