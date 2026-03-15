/*
Scutora Security Platform
Copyright (c) 2026 Joe Miglio

Licensed under the MIT License.
See LICENSE file in the project root for full license information.
*/

import { Link } from "react-router-dom";
import "./App.css";

export default function LandingPage() {
  return (
    <div className="page">
      <div className="container">
        <div className="hero landing-hero">
          <div className="hero-content">
            <div className="badge">Scutora</div>

            <h1>AI-Assisted DMARC Governance</h1>

            <p className="hero-copy">
              Scutora transforms raw DMARC aggregate reports into actionable
              email security insight, including telemetry analysis, sender
              classification, governance recommendations, and exportable reports.
            </p>

            <div className="hero-cta">
              <Link className="cta-button" to="/app">
                Open Dashboard
              </Link>
            </div>
          </div>
        </div>

        <div className="section-card">
          <div className="section-header">
            <h2>What Scutora Does</h2>
          </div>

          <div className="section-body">
            <ul style={{ lineHeight: "1.8" }}>
              <li>Parses DMARC aggregate XML reports</li>
              <li>Summarizes authentication telemetry</li>
              <li>Identifies failing and suspicious senders</li>
              <li>Classifies sender behavior patterns</li>
              <li>Generates governance recommendations</li>
              <li>Exports professional security reports</li>
            </ul>
          </div>
        </div>

        <div className="section-card">
          <div className="section-header">
            <h2>How It Works</h2>
          </div>

          <div className="section-body">
            <ul style={{ lineHeight: "1.8" }}>
              <li>Upload a DMARC aggregate XML report</li>
              <li>Review telemetry, diagnostics, and classified findings</li>
              <li>Assess governance risk as Low, Medium, or High</li>
              <li>Export an executive-ready PDF report</li>
            </ul>
          </div>
        </div>

        <div className="section-card">
          <div className="section-header">
            <h2>Why It Matters</h2>
          </div>

          <div className="section-body">
            <p>
              DMARC aggregate reports contain valuable authentication telemetry,
              but they are often difficult to interpret quickly. Security and
              messaging teams need to understand whether failing senders reflect
              benign misconfiguration, forwarding behavior, or potentially
              unauthorized sending.
            </p>

            <p style={{ marginTop: "12px" }}>
              Scutora converts raw authentication data into structured
              diagnostics and governance insight, helping teams evaluate email
              security posture before increasing DMARC enforcement levels.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}