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

        risk_score = 0
        for f in findings:
            if f.get("severity") == "Critical":
                risk_score += 4
            elif f.get("severity") == "High":
                risk_score += 3
            elif f.get("severity") == "Medium":
                risk_score += 2
            elif f.get("severity") == "Low":
                risk_score += 1

        self.metadata["risk_score"] = risk_score
        self.metadata["risk_percent"] = min(risk_score * 5, 100)

        return findings

    def save_report(self, findings):
        ReportGenerator(self.apk_path).generate(findings, self.metadata)

