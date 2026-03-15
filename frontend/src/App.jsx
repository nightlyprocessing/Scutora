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
	
	File: App.jsx
	
	Updated: March 15th, 2026, 12:18 AM CST
*/

import { useRef, useState } from "react";
import html2canvas from "html2canvas";
import jsPDF from "jspdf";
import "./App.css";

export default function App() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const reportRef = useRef(null);

  const uploadEndpoint = "/api/analyze-upload";

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
          // Ignore JSON parsing issues and fall back to generic message.
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

  function buildPdfFileName() {
    const safeDomain = String(result?.domain || "report")
      .toLowerCase()
      .replace(/[^a-z0-9.-]/g, "-")
      .replace(/-+/g, "-");

    const now = new Date();
    const yyyy = now.getFullYear();
    const mm = String(now.getMonth() + 1).padStart(2, "0");
    const dd = String(now.getDate()).padStart(2, "0");
    const hh = String(now.getHours()).padStart(2, "0");
    const min = String(now.getMinutes()).padStart(2, "0");

    return `scutora-dmarc-report-${safeDomain}-${yyyy}${mm}${dd}-${hh}${min}.pdf`;
  }

  function waitForRender() {
    return new Promise((resolve) => {
      requestAnimationFrame(() => {
        requestAnimationFrame(resolve);
      });
    });
  }

  async function exportToPdf() {
    if (!result) {
      setError("Run an analysis before exporting a PDF.");
      return;
    }

    if (!reportRef.current) {
      setError("Unable to find the report content for export.");
      return;
    }

    setError("");

    try {
      const exportRoot = reportRef.current;
      const pdf = new jsPDF("p", "mm", "a4");

      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      const margin = 10;
      const usableWidth = pageWidth - margin * 2;
      const usableHeight = pageHeight - margin * 2;

      let currentY = margin;
      let isFirstPage = true;

      const sectionNodes = Array.from(
        exportRoot.querySelectorAll("[data-pdf-section='true']")
      );

      async function renderNodeToCanvas(node) {
        await waitForRender();

        return html2canvas(node, {
          scale: 2,
          useCORS: true,
          backgroundColor: "#ffffff",
          logging: false,
          windowWidth: document.documentElement.scrollWidth,
        });
      }

      async function addCanvasToPdf(canvas) {
        const imgWidthMm = usableWidth;
        const imgHeightMm = (canvas.height * imgWidthMm) / canvas.width;
        const remainingSpaceMm = usableHeight - (currentY - margin);

        if (imgHeightMm <= remainingSpaceMm) {
          const imgData = canvas.toDataURL("image/png");
          pdf.addImage(
            imgData,
            "PNG",
            margin,
            currentY,
            imgWidthMm,
            imgHeightMm,
            undefined,
            "FAST"
          );
          currentY += imgHeightMm + 6;
          return;
        }

        if (imgHeightMm <= usableHeight) {
          if (!isFirstPage) {
            pdf.addPage();
          }
          isFirstPage = false;
          currentY = margin;

          const imgData = canvas.toDataURL("image/png");
          pdf.addImage(
            imgData,
            "PNG",
            margin,
            currentY,
            imgWidthMm,
            imgHeightMm,
            undefined,
            "FAST"
          );
          currentY += imgHeightMm + 6;
          return;
        }

        const pxPerMm = canvas.width / imgWidthMm;
        const sliceHeightPx = Math.floor(usableHeight * pxPerMm);

        let renderedHeightPx = 0;
        let firstSlice = true;

        while (renderedHeightPx < canvas.height) {
          const remainingPx = canvas.height - renderedHeightPx;
          const currentSliceHeightPx = Math.min(sliceHeightPx, remainingPx);

          const sliceCanvas = document.createElement("canvas");
          sliceCanvas.width = canvas.width;
          sliceCanvas.height = currentSliceHeightPx;

          const sliceContext = sliceCanvas.getContext("2d");
          if (!sliceContext) {
            throw new Error("Unable to prepare PDF canvas slice.");
          }

          sliceContext.drawImage(
            canvas,
            0,
            renderedHeightPx,
            canvas.width,
            currentSliceHeightPx,
            0,
            0,
            canvas.width,
            currentSliceHeightPx
          );

          const sliceImgData = sliceCanvas.toDataURL("image/png");
          const sliceHeightMm = currentSliceHeightPx / pxPerMm;

          if (firstSlice) {
            if (!isFirstPage && currentY !== margin) {
              pdf.addPage();
            }
            currentY = margin;
          } else {
            pdf.addPage();
            currentY = margin;
          }

          isFirstPage = false;

          pdf.addImage(
            sliceImgData,
            "PNG",
            margin,
            currentY,
            imgWidthMm,
            sliceHeightMm,
            undefined,
            "FAST"
          );

          renderedHeightPx += currentSliceHeightPx;
          firstSlice = false;
        }

        currentY += 6;
      }

      const headerNode = exportRoot.querySelector(".pdf-report-header");
      if (headerNode) {
        const headerCanvas = await renderNodeToCanvas(headerNode);
        await addCanvasToPdf(headerCanvas);
        isFirstPage = false;
      }

      for (const sectionNode of sectionNodes) {
        const sectionCanvas = await renderNodeToCanvas(sectionNode);
        await addCanvasToPdf(sectionCanvas);
      }

      pdf.save(buildPdfFileName());
    } catch (err) {
      setError(err?.message || "Failed to export PDF.");
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
    const nextSteps = actionPlan?.next_steps || [];

    if (nextSteps.length > 0) {
      return nextSteps.map((step) => ({
        title: step.title || "Recommended Step",
        description: step.description || "No description provided.",
        reason: step.reason || "No reason provided.",
      }));
    }

    const fallbackSteps = [];
    const actions = actionPlan?.proposed_actions || [];

    actions.forEach((action) => {
      const recordType = action.record_type || "record";
      const recordName = action.record_name || "DNS record";
      const currentValue = action.current_value || "unknown";
      const proposedValue = action.proposed_value || "unknown";
      const reason = action.reason || "No reason provided.";

      fallbackSteps.push({
        title: `Update ${recordType} ${recordName}`,
        description: `Change the value from "${currentValue}" to "${proposedValue}".`,
        reason,
      });
    });

    return fallbackSteps;
  }

  function formatReasoningSections(text) {
    if (!text) return [];

    return text
      .split(/\n\s*\n/)
      .map((block) => block.trim())
      .filter(Boolean)
      .map((block) => {
        const lines = block
          .split("\n")
          .map((line) => line.trim())
          .filter(Boolean);

        const firstLine = lines[0] || "";
        const body = lines.slice(1).join(" ").trim();

        const cleanedTitle = firstLine
          .replace(/^#+\s*/, "")
          .replace(/^\d+[\.\)]\s*/, "")
          .trim();

        return {
          title: cleanedTitle,
          body,
        };
      });
  }

  const riskClass = getRiskClass(result?.decision?.risk_level);
  const classifiedFindings = result?.diagnostics?.classified_findings || [];
  const actionSteps = buildActionSteps(result?.action_plan);
  const reasoningSections = formatReasoningSections(
    result?.reasoning?.reasoning_summary
  );

  return (
    <div className="page">
      <div className="container">
        <div className="hero no-pdf">
          <div className="hero-content">
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

              {selectedFile ? (
                <div className="selected-file-name">
                  Selected file: {selectedFile.name}
                </div>
              ) : null}

              <button type="button" onClick={runUploadAnalysis} disabled={loading}>
                {loading ? "Uploading..." : "Analyze Uploaded Report"}
              </button>

              <button
                type="button"
                className="secondary-button"
                onClick={exportToPdf}
                disabled={loading || !result}
              >
                Export Dashboard to PDF
              </button>
            </div>

            {loading ? <div className="loading">Running Scutora analysis...</div> : null}
          </div>
        </div>

        <div ref={reportRef} className="report-content pdf-export-surface">
          {result ? (
            <div className="pdf-report-header">
              <div className="pdf-report-brand">Scutora</div>
              <h1>Email Authentication Governance Report</h1>
              <div className="pdf-report-meta">
                <div>
                  <strong>Domain:</strong> {String(result.domain ?? "N/A")}
                </div>
                <div>
                  <strong>Generated:</strong> {new Date().toLocaleString()}
                </div>
              </div>
            </div>
          ) : null}

          <div className="section-card" data-pdf-section="true">
            <div className="section-header">
              <h2>Agent Pipeline</h2>
              <p>How Scutora processes a DMARC report from intake through governance output.</p>
            </div>
            <div className="section-body">
              <div className="pipeline-steps">
                <div className="pipeline-step">Discovery</div>
                <div className="pipeline-arrow">→</div>

                <div className="pipeline-step">Telemetry</div>
                <div className="pipeline-arrow">→</div>

                <div className="pipeline-step">Diagnostics</div>
                <div className="pipeline-arrow">→</div>

                <div className="pipeline-step">Governance</div>
                <div className="pipeline-arrow">→</div>

                <div className="pipeline-step">AI Reasoning</div>
                <div className="pipeline-arrow">→</div>

                <div className="pipeline-step">Action Plan</div>
              </div>
            </div>
          </div>

          {error ? <div className="error-box no-pdf">{error}</div> : null}

          {!result && !loading ? (
            <div className="empty-state no-pdf">
              Upload a DMARC XML report to generate telemetry findings, risk analysis,
              AI reasoning, and recommended governance actions.
            </div>
          ) : null}

          {result ? (
            <div className="grid">
              <div className="section-card" data-pdf-section="true">
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

              <div className="section-card" data-pdf-section="true">
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

              <div className="section-card" data-pdf-section="true">
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

              <div className="section-card" data-pdf-section="true">
                <div className="section-header">
                  <h2>AI Reasoning</h2>
                  <p>Model-generated explanation of the recommendation.</p>
                </div>
                <div className="section-body">
                  {reasoningSections.length > 0 ? (
                    <div className="reasoning-sections">
                      {reasoningSections.map((section, index) => (
                        <div key={index} className="reasoning-section">
                          <div className="reasoning-section-title">{section.title}</div>
                          <div className="reasoning-section-body">
                            {section.body || "No details provided."}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="reasoning-box">
                      {result.reasoning?.reasoning_summary || "No reasoning available."}
                    </div>
                  )}
                </div>
              </div>

              <div className="section-card" data-pdf-section="true">
                <div className="section-header">
                  <h2>Action Plan</h2>
                  <p>Concrete next steps based on the current findings.</p>
                </div>
                <div className="section-body">
                  {!result?.action_plan ? (
                    <div className="empty-inline">No action plan available.</div>
                  ) : (
                    <>
                      <div className="card action-meta-card">
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
                            <div key={index} className="card action-step-card">
                              <div className="step-number">Step {index + 1}</div>
                              <div className="action-step-title">{step.title}</div>
                              <div className="action-step-description">{step.description}</div>
                              <div className="action-step-reason">
                                <strong>Why:</strong> {step.reason}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}

                      {result.action_plan?.proposed_actions?.length ? (
                        <div className="section-card nested-card">
                          <div className="section-header">
                            <h2>Technical Change Details</h2>
                            <p>Structured implementation details for the recommended DNS change.</p>
                          </div>
                          <div className="section-body">
                            {result.action_plan.proposed_actions.map((action, index) => (
                              <div key={index} className="card technical-detail-card">
                                <div>
                                  <strong>System:</strong> {action.system || "N/A"}
                                </div>
                                <div>
                                  <strong>Action:</strong> {action.action || "N/A"}
                                </div>
                                <div>
                                  <strong>Record Type:</strong> {action.record_type || "N/A"}
                                </div>
                                <div>
                                  <strong>Record Name:</strong> {action.record_name || "N/A"}
                                </div>
                                <div>
                                  <strong>Current Value:</strong> {action.current_value || "N/A"}
                                </div>
                                <div>
                                  <strong>Proposed Value:</strong> {action.proposed_value || "N/A"}
                                </div>
                                <div>
                                  <strong>Reason:</strong> {action.reason || "N/A"}
                                </div>
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
    </div>
  );
}