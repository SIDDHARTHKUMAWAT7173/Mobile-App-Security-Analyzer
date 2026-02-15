OWASP_MOBILE_TOP_10_2024 = {
    "M1": "Improper Credential Usage",
    "M2": "Insecure Data Storage",
    "M3": "Insecure Communication",
    "M4": "Insecure Authentication",
    "M5": "Insufficient Authorization",
    "M6": "Insufficient Privacy Controls",
    "M7": "Insufficient Binary Protections",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Integrity",
    "M10": "Insufficient Cryptography"
}


def format_owasp(category_code):
    name = OWASP_MOBILE_TOP_10_2024.get(category_code, "Unknown")
    return f"{category_code} - {name}"
