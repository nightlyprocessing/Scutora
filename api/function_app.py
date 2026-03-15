# Scutora Security Platform
# Copyright (c) 2026 Joe Miglio
#
# Licensed under the MIT License.
# See the LICENSE file in the project root for license information.

import json
import tempfile
import azure.functions as func

from orchestrator import run_scutora_analysis

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="ping", methods=["GET"])
def ping(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse("pong", status_code=200)

@app.route(route="analyze")
def analyze(req: func.HttpRequest) -> func.HttpResponse:
    domain = req.params.get("domain", "scutora.com")

    result = run_scutora_analysis(
        xml_file="sample_dmarc.xml",
        domain=domain,
        use_mock_m365=True,
        use_mock_gandi=True
    )

    return func.HttpResponse(
        json.dumps(result, indent=2),
        mimetype="application/json",
        status_code=200
    )


@app.route(route="analyze-upload", methods=["POST"])
def analyze_upload(req: func.HttpRequest) -> func.HttpResponse:
    try:
        file_bytes = req.get_body()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name

        domain = req.params.get("domain", "scutora.com")

        result = run_scutora_analysis(
            xml_file=tmp_path,
            domain=domain,
            use_mock_m365=True,
            use_mock_gandi=True
        )

        return func.HttpResponse(
            json.dumps(result, indent=2),
            mimetype="application/json",
            status_code=200
        )

    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            mimetype="application/json",
            status_code=500
        )
