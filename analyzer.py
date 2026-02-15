import hashlib
from androguard.misc import AnalyzeAPK
from scanners.manifest import ManifestScanner
from scanners.permissions import PermissionScanner
from scanners.crypto import CryptoScanner
from scanners.secrets import SecretScanner
from utils.report import ReportGenerator


class APKAnalyzer:

    def calculate_sha256(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()


    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk = None
        self.dex = None
        self.analysis = None
        self.metadata = {}


    def load_apk(self):
        print("[*] Loading APK...")
        self.apk, self.dex, self.analysis = AnalyzeAPK(self.apk_path)
        print("[+] APK loaded successfully.")

        self.metadata = {
            "package_name": self.apk.get_package(),
            "version_name": self.apk.get_androidversion_name(),
            "version_code": self.apk.get_androidversion_code(),
            "min_sdk": self.apk.get_min_sdk_version(),
            "target_sdk": self.apk.get_target_sdk_version(),
            "sha256": self.calculate_sha256(self.apk_path)
    }


    def run_analysis(self):
        self.load_apk()

        findings = []

        print("[*] Running manifest checks...")
        findings.extend(ManifestScanner(self.apk).scan())

        print("[*] Running permission checks...")
        findings.extend(PermissionScanner(self.apk).scan())

        print("[*] Running crypto checks...")
        findings.extend(CryptoScanner(self.analysis).scan())

        print("[*] Running secret detection...")
        findings.extend(SecretScanner(self.analysis).scan())

        # -------------------------------
        # Advanced Risk Scoring Engine
        # -------------------------------

        severity_weights = {
            "Critical": 10,
            "High": 7,
            "Medium": 4,
            "Low": 1
        }

        risk_score = 0

        for f in findings:
            severity = f.get("severity")
            risk_score += severity_weights.get(severity, 0)

        # Risk level classification
        if risk_score >= 60:
            risk_level = "Critical"
        elif risk_score >= 40:
            risk_level = "High"
        elif risk_score >= 20:
            risk_level = "Moderate"
        else:
            risk_level = "Low"

        self.metadata["risk_score"] = risk_score
        self.metadata["risk_level"] = risk_level
        self.metadata["risk_percent"] = min(risk_score, 100)


        return findings

    def save_report(self, findings):
        ReportGenerator(self.apk_path).generate(findings, self.metadata)

