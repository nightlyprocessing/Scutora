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
