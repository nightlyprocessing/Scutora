# Scutora Security Platform
# Copyright (c) 2026 Joe Miglio
#
# Licensed under the MIT License.
# See the LICENSE file in the project root for license information.

import hmac
import json
import os

import azure.functions as func

from orchestrator import run_scutora_analysis


MAX_XML_UPLOAD_BYTES = 1_048_576
API_KEY_HEADER = "x-scutora-api-key"

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)


def _authorization_error(req):
    configured_key = os.getenv("SCUTORA_API_KEY")
    if not configured_key:
        return func.HttpResponse(
            json.dumps({"error": "Scutora API authentication is not configured."}),
            mimetype="application/json",
            status_code=503
        )

    supplied_key = req.headers.get(API_KEY_HEADER, "")
    if not hmac.compare_digest(supplied_key, configured_key):
        return func.HttpResponse(
            json.dumps({"error": "Authentication required."}),
            mimetype="application/json",
            status_code=401
        )

    return None


@app.route(route="ping", methods=["GET"])
def ping(req: func.HttpRequest) -> func.HttpResponse:
    auth_error = _authorization_error(req)
    if auth_error:
        return auth_error
    return func.HttpResponse("pong", status_code=200)


@app.route(route="analyze", methods=["GET"])
def analyze(req: func.HttpRequest) -> func.HttpResponse:
    auth_error = _authorization_error(req)
    if auth_error:
        return auth_error

    try:
        result = run_scutora_analysis(
            xml_file="sample_dmarc.xml",
            domain=req.params.get("domain", "scutora.com"),
            use_mock_m365=True,
            use_mock_gandi=True
        )
        return func.HttpResponse(
            json.dumps(result, indent=2),
            mimetype="application/json",
            status_code=200
        )
    except Exception:
        return func.HttpResponse(
            json.dumps({"error": "Analysis could not be completed."}),
            mimetype="application/json",
            status_code=400
        )


@app.route(route="analyze-upload", methods=["POST"])
def analyze_upload(req: func.HttpRequest) -> func.HttpResponse:
    auth_error = _authorization_error(req)
    if auth_error:
        return auth_error

    content_length = req.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_XML_UPLOAD_BYTES:
                return func.HttpResponse(
                    json.dumps({"error": "XML uploads must be 1 MiB or smaller."}),
                    mimetype="application/json",
                    status_code=413
                )
        except ValueError:
            return func.HttpResponse(
                json.dumps({"error": "Invalid Content-Length header."}),
                mimetype="application/json",
                status_code=400
            )

    file_bytes = req.get_body()
    if not file_bytes or len(file_bytes) > MAX_XML_UPLOAD_BYTES:
        return func.HttpResponse(
            json.dumps({"error": "XML uploads must be between 1 byte and 1 MiB."}),
            mimetype="application/json",
            status_code=413 if len(file_bytes) > MAX_XML_UPLOAD_BYTES else 400
        )

    try:
        result = run_scutora_analysis(
            xml_file=file_bytes,
            domain=req.params.get("domain", "scutora.com"),
            use_mock_m365=True,
            use_mock_gandi=True
        )
        return func.HttpResponse(
            json.dumps(result, indent=2),
            mimetype="application/json",
            status_code=200
        )
    except Exception:
        return func.HttpResponse(
            json.dumps({"error": "The uploaded report is invalid or could not be analyzed."}),
            mimetype="application/json",
            status_code=400
        )
