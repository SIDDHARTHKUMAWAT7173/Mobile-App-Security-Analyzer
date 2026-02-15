import json
import os
from datetime import datetime
from utils.severity import calculate_risk_score



class ReportGenerator:

    def __init__(self, apk_path):
        self.apk_path = apk_path

    def generate(self, findings, metadata):
        summary = self._generate_summary(findings)
        risk_score = calculate_risk_score(summary)

        report = {
            "apk_name": os.path.basename(self.apk_path),
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "metadata": metadata,
            "total_issues": len(findings),
            "risk_score": risk_score,
            "summary": summary,
            "findings": findings

        }

        with open("security_report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)

        print("[+] Report saved as security_report.json")

    def _generate_summary(self, findings):
        severity_count = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        }

        for finding in findings:
            severity = finding.get("severity")
            if severity in severity_count:
                severity_count[severity] += 1

        return severity_count
