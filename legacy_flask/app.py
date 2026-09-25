from flask import (
    Flask,
    render_template,
    request,
    abort,
    jsonify
)

import os

from parser import AuditParser
from relationship import RelationshipBuilder
from report_generator import ReportGenerator

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Temporary in-memory storage
CURRENT_SUMMARY = None
CURRENT_REPORTS = {}
CURRENT_GENERATOR = None


@app.route("/")
def home():
    return render_template("upload.html")


@app.route("/upload", methods=["POST"])
def upload():

    global CURRENT_SUMMARY
    global CURRENT_REPORTS
    global CURRENT_GENERATOR

    if "json_file" not in request.files:
        return "No file selected"

    file = request.files["json_file"]

    if file.filename == "":
        return "No file selected"

    if not file.filename.lower().endswith(".json"):
        return "Please upload a JSON file."

    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        file.filename
    )

    file.save(filepath)

    parser = AuditParser(filepath)

    summary, findings = parser.parse()

    builder = RelationshipBuilder(findings)

    reports = builder.build()

    generator = ReportGenerator(
        summary,
        reports
    )

    CURRENT_SUMMARY = summary
    CURRENT_REPORTS = reports
    CURRENT_GENERATOR = generator

    dashboard = generator.namespace_summary()

    load_balancers = []

    for lb in reports.values():

        load_balancers.append(
            generator.lb_summary(lb)
        )

    load_balancers = sorted(
        load_balancers,
        key=lambda x: x["name"].lower()
    )

    return render_template(
        "dashboard.html",
        dashboard=dashboard,
        load_balancers=load_balancers
    )


@app.route("/report/<lb_name>")
def report(lb_name):

    if lb_name not in CURRENT_REPORTS:
        abort(404)

    lb = CURRENT_REPORTS[lb_name]

    summary = CURRENT_GENERATOR.lb_summary(lb)

    grouped = CURRENT_GENERATOR.group_findings(lb)

    recommendations = CURRENT_GENERATOR.recommendations(lb)

    return render_template(
        "report.html",
        summary=summary,
        grouped=grouped,
        recommendations=recommendations
    )


@app.route("/namespace")
def namespace_report():

    if CURRENT_GENERATOR is None:
        abort(404)

    dashboard = CURRENT_GENERATOR.namespace_summary()

    return render_template(
        "namespace_report.html",
        dashboard=dashboard
    )


@app.route("/api/loadbalancers")
def api_loadbalancers():

    data = []

    for lb in CURRENT_REPORTS.values():

        data.append(
            CURRENT_GENERATOR.lb_summary(lb)
        )

    return jsonify(data)


@app.route("/api/selected", methods=["POST"])
def selected_reports():

    body = request.get_json()

    selected = body.get("loadbalancers", [])

    reports = []

    for name in selected:

        if name not in CURRENT_REPORTS:
            continue

        lb = CURRENT_REPORTS[name]

        reports.append(
            CURRENT_GENERATOR.lb_summary(lb)
        )

    return jsonify(reports)


if __name__ == "__main__":
    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )