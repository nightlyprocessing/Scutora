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
  const [domain, setDomain] = useState("scutora.com");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);

const analyzeEndpoint = useMemo(() => {
  return `/api/analyze?domain=${encodeURIComponent(
    domain || "scutora.com"
  )}`;
}, [domain]);

const uploadEndpoint = useMemo(() => {
  return `/api/analyze-upload?domain=${encodeURIComponent(
    domain || "scutora.com"
  )}`;
}, [domain]);

  async function runAnalysis() {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(analyzeEndpoint);
      if (!response.ok) {
        throw new Error(`Request failed with status ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err?.message || "Failed to call Scutora backend.");
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  async function runUploadAnalysis() {
    if (!selectedFile) {
      setError("Please choose a DMARC XML file first.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const fileText = await selectedFile.text();

      const response = await fetch(uploadEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/xml"
        },
        body: fileText
      });

      if (!response.ok) {
        throw new Error(`Upload request failed with status ${response.status}`);
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

  const riskClass = getRiskClass(result?.decision?.risk_level);
  const classifiedFindings = result?.diagnostics?.classified_findings || [];

  return (
    <div className="page">
      <div className="container">
        <div className="demo-banner">
          Demo Mode: Scutora analyzes DMARC telemetry and proposes safe authentication policy changes.
        </div>

        <div className="hero">
          <div>
            <div className="badge">Scutora</div>
            <h1>Email Authentication Governance Dashboard</h1>
            <p className="hero-copy">
              Multi-step analysis for DMARC telemetry, posture discovery,
              diagnostics, policy recommendation, reasoning, and action
              planning.
            </p>
          </div>

          <div className="control-card">
            <label htmlFor="domain">Domain</label>
            <input
              id="domain"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="scutora.com"
            />

            <button onClick={runAnalysis} disabled={loading}>
              {loading ? "Analyzing..." : "Analyze Domain"}
            </button>

            <div className="upload-block">
              <label htmlFor="xmlfile">DMARC XML Upload</label>
              <input
                id="xmlfile"
                type="file"
                accept=".xml,text/xml,application/xml"
                onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
              />
              <button onClick={runUploadAnalysis} disabled={loading}>
                {loading ? "Uploading..." : "Analyze Uploaded Report"}
              </button>
            </div>

            {loading ? <div className="loading">Running Scutora analysis...</div> : null}

            <p className="endpoint">{analyzeEndpoint}</p>
            <p className="endpoint">{uploadEndpoint}</p>
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
            Enter a domain and either click <strong>Analyze Domain</strong> or
            upload a DMARC XML report.
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
                    <div className="pill-value">{String(result.summary?.total_messages ?? "N/A")}</div>
                  </div>
                  <div className="card">
                    <div className="pill-label">DKIM Pass Count</div>
                    <div className="pill-value">{String(result.summary?.dkim_pass_count ?? "N/A")}</div>
                  </div>
                  <div className="card">
                    <div className="pill-label">SPF Pass Count</div>
                    <div className="pill-value">{String(result.summary?.spf_pass_count ?? "N/A")}</div>
                  </div>
                  <div className="card">
                    <div className="pill-label">DKIM Pass Rate</div>
                    <div className="pill-value">{String(result.summary?.dkim_pass_rate ?? "N/A")}%</div>
                  </div>
                  <div className="card">
                    <div className="pill-label">SPF Pass Rate</div>
                    <div className="pill-value">{String(result.summary?.spf_pass_rate ?? "N/A")}%</div>
                  </div>
                  <div className="card">
                    <div className="pill-label">Failing Senders</div>
                    <div className="pill-value">{String(result.diagnostics?.failing_sender_count ?? "N/A")}</div>
                  </div>
                  <div className="card">
                    <div className="pill-label">Suspicious Senders</div>
                    <div className="pill-value">{String(result.diagnostics?.suspicious_sender_count ?? "N/A")}</div>
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
                <p>Proposed next steps requiring human approval.</p>
              </div>
              <div className="section-body">
                <pre className="code-block">
                  {JSON.stringify(result.action_plan, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}