# Scutora Architecture (Draft)

Scutora is a multi-agent platform that evaluates email authentication posture and recommends staged DMARC enforcement.

## Core Components

### Discovery Agent
Retrieves domain authentication configuration via Microsoft Graph.

### Telemetry Agent
Parses DMARC aggregate reports and extracts alignment metrics.

### Risk Agent
Evaluates enforcement readiness using simple heuristics.

### Orchestrator
Coordinates agents and produces a policy recommendation.

## Azure Components (Planned)

- Azure Functions
- Azure Storage
- Microsoft Agent Framework
- Microsoft Graph API
