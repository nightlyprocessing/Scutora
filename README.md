# Scutora
Agent-based email authentication governance prototype

Scutora is an experimental multi-agent platform designed to observe domain authentication telemetry and recommend staged enforcement of SPF, DKIM, and DMARC policies.

This project is being developed as part of the 2026 Microsoft AI Dev Days Hackathon.

## Concept

Organizations often remain stuck at DMARC `p=none` due to uncertainty about enforcement risks.  
Scutora uses a multi-agent system to:

- Discover domain authentication configuration
- Analyze DMARC telemetry
- Model enforcement risk
- Recommend staged policy transitions

## Planned Architecture

Agents:
- Discovery Agent – Reads domain configuration via Microsoft Graph
- Telemetry Agent – Parses DMARC aggregate reports
- Risk Agent – Evaluates alignment metrics
- Orchestrator – Coordinates agents and produces enforcement recommendations

Built with:
- Azure
- Microsoft Agent Framework
- GitHub

## Project Site

https://www.scutora.com

## Sample Reports

Example DMARC aggregate reports are included in /sample-reports.

These can be uploaded directly into the Scutora dashboard for testing.

## License

MIT License


## Private API configuration

The API rejects requests unless the Azure Functions application setting
`SCUTORA_API_KEY` is configured. Generate a unique high-entropy value, add it
as an application setting in the Function App configuration, and enter the same
value in the dashboard's API Key field. The dashboard keeps it only in the
current browser tab's session storage and sends it in the
`X-Scutora-Api-Key` request header. Do not commit the key or place it in
frontend build settings.

For example, generate a 256-bit key with:

```sh
openssl rand -hex 32
```

Keep the Function App and Static Web App on HTTPS. If the API key is missing,
the API fails closed. XML uploads are limited to 1 MiB, parsed with
`defusedxml`, and are not written to temporary files.
