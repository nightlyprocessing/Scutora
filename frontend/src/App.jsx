/*
    Scutora Security Platform
    Copyright (c) 2026 Joe Miglio. All rights reserved.

    This source code is part of the Scutora project and contains
    proprietary and confidential information belonging to Joe Miglio.

    Unauthorized copying, modification, distribution, reverse engineering,
    or disclosure of this file, in whole or in part, is strictly prohibited
    without the prior written permission of the copyright holder.

    This software may include trade secrets and proprietary techniques
    related to domain intelligence, threat analysis, and AI-driven security
    automation developed as part of the Scutora platform.
*/

import { useMemo, useState } from "react";
import "./App.css";

export default function App() {
  const [domain, setDomain] = useState("nightlyprocessing.com");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);

  const uploadEndpoint = useMemo(() => {
    return `/api/analyze-upload?domain=${encodeURIComponent(
      domain || "nightlyprocessing.com"
    )}`;
  }, [domain]);

  async function runUploadAnalysis() {
    if (!selectedFile) {
      setError("Please choose a DMARC XML file first.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const response = await fetch(uploadEndpoint, {
        method: "POST",
        body: selectedFile,
      });

      if (!response.ok) {
        let errorMessage = `Upload request failed with status ${response.status}`;

        try {
          const errorData = await response.json();
          if (errorData?.error) {
            errorMessage = errorData.error;
          }
        } catch {
          // Ignore JSON parse issues and fall back to the generic message.
        }

        throw new Error(errorMessage);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err?.message || "Failed to upload DMARC report.");
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  function getRiskClass(riskLevel) {
    const normalized = String(riskLevel || "").toLowerCase();

    if (normalized === "high") return "risk-high";
    if (normalized === "medium") return "risk-medium";
    if (normalized === "low") return "risk-low";
    return "risk-unknown";
  }

  function getClassificationClass(classification) {
    const normalized = String(classification || "").toLowerCase();

    if (normalized === "likely_misconfiguration") return "class-misconfig";
    if (normalized === "potentially_unauthorized_sender") return "class-unauthorized";
    if (normalized === "manual_review_required") return "class-review";
    return "class-unknown";
  }

  function buildActionSteps(actionPlan) {
    const steps = [];
    const actions = actionPlan?.proposed_actions || [];

    actions.forEach((action) => {
      const recordType = action.record_type || "record";
      const recordName = action.record_name || "DNS record";
      const currentValue = action.current_value || "unknown";
      const proposedValue = action.proposed_value || "unknown";
      const reason = action.reason || "No reason provided.";

      steps.push({
        title: `Update ${recordType} ${recordName}`,
        description: `Change the value from "${currentValue}" to "${proposedValue}".`,
        reason,
      });
    });

    if (actions.length > 0) {
      steps.push({
        title: "Validate mail flow after the change",
        description:
          "Monitor aggregate reports and confirm legitimate sending sources continue to authenticate successfully after the DNS update is published.",
        reason:
          "Authentication policy changes should be introduced carefully to avoid disrupting valid email traffic.",
      });

      if (actionPlan?.approval_required) {
        steps.push({
          title: "Obtain approval before implementation",
          description:
            "Have the recommended governance change reviewed and approved before applying it in production.",
          reason:
            "Email authentication policy changes can affect business-critical mail flow and should require human review.",
        });
      }
    }

    return steps;
  }

  const riskClass = getRiskClass(result?.decision?.risk_level);
  const classifiedFindings = result?.diagnostics?.classified_findings || [];
  const actionSteps = buildActionSteps(result?.action_plan);

  return (
    <div className="page">
      <div className="container">
        <div className="hero">
          <div>
            <div className="badge">Scutora</div>
            <h1>Email Authentication Governance Dashboard</h1>
            <p className="hero-copy">
              Upload a DMARC aggregate XML report to evaluate authentication posture,
              identify suspicious sender behavior, and generate governance
              recommendations with AI-assisted reasoning.
            </p>
          </div>

          <div className="control-card">
            <div className="upload-block">
              <label htmlFor="xmlfile">DMARC XML Upload</label>
              <input
                id="xmlfile"
                type="file"
                accept=".xml,text/xml,application/xml"
                onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
              />
              <button type="button" onClick={runUploadAnalysis} disabled={loading}>
                {loading ? "Uploading..." : "Analyze Uploaded Report"}
              </button>
            </div>

            {loading ? <div className="loading">Running Scutora analysis...</div> : null}
          </div>
        </div>

        <div className="section-card">
          <div className="section-header">
            <h2>Agent Pipeline</h2>
            <p>How Scutora analyzes and governs email authentication posture.</p>
          </div>
          <div className="section-body">
            <div className="pipeline">
              Discovery → Telemetry → Diagnostics → Governance → AI Reasoning → Action Plan
            </div>
          </div>
        </div>

        {error ? <div className="error-box">{error}</div> : null}

        {!result && !loading ? (
          <div className="empty-state">
            Upload a DMARC XML report to generate telemetry findings, risk analysis,
            AI reasoning, and recommended governance actions.
          </div>
        ) : null}

        {result ? (
          <div className="grid">
            <div className="section-card">
              <div className="section-header">
                <h2>Executive Summary</h2>
                <p>Top-level outcome from the current analysis.</p>
              </div>
              <div className="section-body">
                <div className="pill-grid">
                  <div className="card">
                    <div className="pill-label">Domain</div>
                    <div className="pill-value">{String(result.domain ?? "N/A")}</div>
                  </div>

                  <div className={`card ${riskClass}`}>
                    <div className="pill-label">Risk Level</div>
                    <div className="pill-value">
                      {String(result.decision?.risk_level ?? "N/A")}
                    </div>
                  </div>

                  <div className="card">
                    <div className="pill-label">Recommendation</div>
                    <div className="pill-value">
                      {String(result.decision?.recommendation ?? "N/A")}
                    </div>
                  </div>

                  <div className="card">
                    <div className="pill-label">Approval Required</div>
                    <div className="pill-value">
                      {String(result.action_plan?.approval_required ?? "N/A")}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="section-card">
              <div className="section-header">
                <h2>Telemetry Summary</h2>
                <p>Aggregated DMARC telemetry metrics.</p>
              </div>
              <div className="section-body">
                <div className="pill-grid wide">
                  <div className="card">
                    <div className="pill-label">Total Messages</div>
                    <div className="pill-value">
                      {String(result.summary?.total_messages ?? "N/A")}
                    </div>
                  </div>
                  <div className="card">
                    <div className="pill-label">DKIM Pass Count</div>
                    <div className="pill-value">
                      {String(result.summary?.dkim_pass_count ?? "N/A")}
                    </div>
                  </div>
                  <div className="card">
                    <div className="pill-label">SPF Pass Count</div>
                    <div className="pill-value">
                      {String(result.summary?.spf_pass_count ?? "N/A")}
                    </div>
                  </div>
                  <div className="card">
                    <div className="pill-label">DKIM Pass Rate</div>
                    <div className="pill-value">
                      {String(result.summary?.dkim_pass_rate ?? "N/A")}%
                    </div>
                  </div>
                  <div className="card">
                    <div className="pill-label">SPF Pass Rate</div>
                    <div className="pill-value">
                      {String(result.summary?.spf_pass_rate ?? "N/A")}%
                    </div>
                  </div>
                  <div className="card">
                    <div className="pill-label">Failing Senders</div>
                    <div className="pill-value">
                      {String(result.diagnostics?.failing_sender_count ?? "N/A")}
                    </div>
                  </div>
                  <div className="card">
                    <div className="pill-label">Suspicious Senders</div>
                    <div className="pill-value">
                      {String(result.diagnostics?.suspicious_sender_count ?? "N/A")}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="section-card">
              <div className="section-header">
                <h2>Classified Findings</h2>
                <p>Diagnostics agent classifications for failing sender patterns.</p>
              </div>
              <div className="section-body">
                {classifiedFindings.length === 0 ? (
                  <div className="empty-inline">No classified findings.</div>
                ) : (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Source IP</th>
                          <th>Count</th>
                          <th>DKIM</th>
                          <th>SPF</th>
                          <th>Classification</th>
                          <th>Reason</th>
                        </tr>
                      </thead>
                      <tbody>
                        {classifiedFindings.map((finding, index) => (
                          <tr key={`${finding.source_ip}-${index}`}>
                            <td>{finding.source_ip}</td>
                            <td>{finding.count}</td>
                            <td>{finding.dkim}</td>
                            <td>{finding.spf}</td>
                            <td>
                              <span
                                className={`classification-pill ${getClassificationClass(
                                  finding.classification
                                )}`}
                              >
                                {finding.classification}
                              </span>
                            </td>
                            <td>{finding.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>

            <div className="section-card">
              <div className="section-header">
                <h2>AI Reasoning</h2>
                <p>Model-generated explanation of the recommendation.</p>
              </div>
              <div className="section-body">
                <div className="reasoning-box">
                  {result.reasoning?.reasoning_summary || "No reasoning available."}
                </div>
              </div>
            </div>

            <div className="section-card">
              <div className="section-header">
                <h2>Action Plan</h2>
                <p>Concrete next steps based on the current findings.</p>
              </div>
              <div className="section-body">
                {!result?.action_plan ? (
                  <div className="empty-inline">No action plan available.</div>
                ) : (
                  <>
                    <div className="card" style={{ marginBottom: "1rem" }}>
                      <div className="pill-label">Approval Required</div>
                      <div className="pill-value">
                        {String(result.action_plan?.approval_required ?? "N/A")}
                      </div>
                    </div>

                    {actionSteps.length === 0 ? (
                      <div className="empty-inline">No concrete action steps available.</div>
                    ) : (
                      <div className="action-steps">
                        {actionSteps.map((step, index) => (
                          <div key={index} className="card" style={{ marginBottom: "1rem" }}>
                            <div className="pill-label">Step {index + 1}</div>
                            <div className="pill-value" style={{ marginBottom: ".5rem" }}>
                              {step.title}
                            </div>
                            <div>{step.description}</div>
                            <div style={{ marginTop: ".5rem", opacity: 0.85 }}>
                              <strong>Why:</strong> {step.reason}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {result.action_plan?.proposed_actions?.length ? (
                      <div className="section-card" style={{ marginTop: "1rem" }}>
                        <div className="section-header">
                          <h2>Technical Change Details</h2>
                          <p>Structured implementation details for the recommended DNS change.</p>
                        </div>
                        <div className="section-body">
                          {result.action_plan.proposed_actions.map((action, index) => (
                            <div key={index} className="card" style={{ marginBottom: "1rem" }}>
                              <div><strong>Record Type:</strong> {action.record_type || "N/A"}</div>
                              <div><strong>Record Name:</strong> {action.record_name || "N/A"}</div>
                              <div><strong>Current Value:</strong> {action.current_value || "N/A"}</div>
                              <div><strong>Proposed Value:</strong> {action.proposed_value || "N/A"}</div>
                              <div><strong>Reason:</strong> {action.reason || "N/A"}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : null}
                  </>
                )}
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
