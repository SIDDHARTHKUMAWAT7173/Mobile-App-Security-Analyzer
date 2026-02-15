from flask import Flask, render_template, request
import os
from analyzer import APKAnalyzer

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    if "apkfile" not in request.files:
        return "No file uploaded"

    file = request.files["apkfile"]

    if file.filename == "":
        return "No selected file"

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(filepath)

    analyzer = APKAnalyzer(filepath)

    findings = analyzer.run_analysis()
    analyzer.save_report(findings)

    return render_template(
        "report.html",
        findings=findings,
        metadata=analyzer.metadata
    )


if __name__ == "__main__":
    app.run(debug=True)
