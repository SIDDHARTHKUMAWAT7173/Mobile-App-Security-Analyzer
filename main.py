import sys
from analyzer import APKAnalyzer

def banner():
    print("\n==============================")
    print("  Mobile App Security Analyzer")
    print("  Static OWASP Scanner")
    print("==============================\n")

def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <apk_file>")
        sys.exit(1)

    apk_path = sys.argv[1]

    banner()

    analyzer = APKAnalyzer(apk_path)
    findings = analyzer.run_analysis()
    analyzer.save_report(findings)

    print("\nScan Complete.")
    print("Report saved as security_report.json\n")

if __name__ == "__main__":
    main()
