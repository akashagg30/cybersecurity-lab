#!/usr/bin/env python3
"""
Security Assessment Report Generator

Generates professional HTML, JSON, and Markdown reports from
recon, web_scanner, and api_tester JSON output.

Usage:
    python report_generator.py recon.json web_scanner.json api_tester.json
    python report_generator.py *.json --format html --output report.html
    python report_generator.py scan.json --format markdown
    python report_generator.py scan.json --format pdf
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}

SEVERITY_BG = {
    "critical": "#fef2f2",
    "high": "#fff7ed",
    "medium": "#fffbeb",
    "low": "#eff6ff",
    "info": "#f9fafb",
}

CVSS_BASE_VECTOR_TEMPLATES = {
    "SQL Injection": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "Cross-Site Scripting (Reflected)": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "Cross-Site Scripting (Stored)": "AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
    "Cross-Site Scripting (DOM-Based)": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Broken Authentication": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "Missing Security Headers": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "Directory Traversal": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CSRF": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "IDOR": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "Rate Limiting Bypass": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "Mass Assignment": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "Information Disclosure": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "Open Redirect": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "Insecure Direct Object Reference": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CVSSScore:
    vector: str
    score: float
    rating: str


@dataclass
class Finding:
    vuln_type: str
    severity: str
    url: str
    description: str
    remediation: str
    evidence: str = ""
    parameter: str = ""
    payload: str = ""
    method: str = ""
    endpoint: str = ""
    response_code: int = 0
    response_time: float = 0.0
    cvss: CVSSScore | None = None


@dataclass
class ScanSummary:
    tool: str
    target: str
    timestamp: str
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# CVSS calculator
# ---------------------------------------------------------------------------

class CVSSCalculator:
    """Lightweight CVSS v3.1 base score calculator."""

    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}

    @classmethod
    def parse_vector(cls, vector: str) -> dict[str, str]:
        metrics = {}
        for part in vector.strip().split("/"):
            if ":" in part:
                key, val = part.split(":", 1)
                metrics[key] = val
        return metrics

    @classmethod
    def calculate(cls, vector: str) -> CVSSScore:
        m = cls.parse_vector(vector)

        av = cls.AV_WEIGHTS.get(m.get("AV", "N"), 0.85)
        ac = cls.AC_WEIGHTS.get(m.get("AC", "L"), 0.77)
        ui = cls.UI_WEIGHTS.get(m.get("UI", "N"), 0.85)

        scope_changed = m.get("S", "U") == "C"
        pr_weights = cls.PR_WEIGHTS_CHANGED if scope_changed else cls.PR_WEIGHTS_UNCHANGED
        pr = pr_weights.get(m.get("PR", "N"), 0.85)

        cia = {"N": 0.00, "L": 0.22, "H": 0.56}
        c = cia.get(m.get("C", "N"), 0.00)
        i = cia.get(m.get("I", "N"), 0.00)
        a = cia.get(m.get("A", "N"), 0.00)

        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            score = 0.0
        else:
            if scope_changed:
                score = min(1.08 * (impact + exploitability), 10.0)
            else:
                score = min(impact + exploitability, 10.0)

        score = round(score, 1)

        if score == 0:
            rating = "None"
        elif score <= 3.9:
            rating = "Low"
        elif score <= 6.9:
            rating = "Medium"
        elif score <= 8.9:
            rating = "High"
        else:
            rating = "Critical"

        return CVSSScore(vector=vector, score=score, rating=rating)

    @classmethod
    def estimate_for_finding(cls, finding: dict[str, Any]) -> CVSSScore:
        """Estimate a CVSS score based on vuln_type if no vector provided."""
        vuln = finding.get("vuln_type", "")
        severity = finding.get("severity", "info")

        vector = CVSS_BASE_VECTOR_TEMPLATES.get(vuln)
        if not vector:
            severity_scores = {
                "critical": 9.5,
                "high": 7.5,
                "medium": 5.0,
                "low": 2.5,
                "info": 0.0,
            }
            score = severity_scores.get(severity, 0.0)
            rating = severity.capitalize() if severity != "info" else "None"
            return CVSSScore(vector="N/A", score=score, rating=rating)

        return cls.calculate(vector)


# ---------------------------------------------------------------------------
# Report data builder
# ---------------------------------------------------------------------------

class ReportBuilder:
    """Aggregates data from multiple scan JSON files into a unified model."""

    def __init__(self):
        self.scans: list[ScanSummary] = []
        self.all_findings: list[Finding] = []
        self.severity_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
        self.tool_results: dict[str, dict] = {}

    def add_json_file(self, filepath: str) -> None:
        try:
            with open(filepath) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"[!] Failed to parse {filepath}: {exc}", file=sys.stderr)
            return

        self.tool_results[filepath] = data

        if "subdomains" in data or "ports" in data:
            self._parse_recon(data)
        elif "api_type" in data or "endpoints_found" in data:
            self._parse_api_tester(data)
        elif "findings" in data:
            self._parse_web_scanner(data)
        else:
            self._parse_generic(data)

    def _parse_recon(self, data: dict) -> None:
        summary_data = data.get("summary", {})
        scan = ScanSummary(
            tool="Recon",
            target=data.get("domain", "Unknown"),
            timestamp=data.get("timestamp", ""),
            stats=summary_data,
            raw=data,
        )
        self.scans.append(scan)

    def _parse_web_scanner(self, data: dict) -> None:
        summary_data = data.get("summary", {})
        scan = ScanSummary(
            tool="Web Scanner",
            target=data.get("target", "Unknown"),
            timestamp=data.get("timestamp", ""),
            stats=summary_data,
            raw=data,
        )
        for f in data.get("findings", []):
            finding = self._finding_from_dict(f)
            cvss = CVSSCalculator.estimate_for_finding(f)
            finding.cvss = cvss
            scan.findings.append(finding)
            self.all_findings.append(finding)
            self.severity_counts[finding.severity] = self.severity_counts.get(finding.severity, 0) + 1
        self.scans.append(scan)

    def _parse_api_tester(self, data: dict) -> None:
        summary_data = data.get("summary", {})
        scan = ScanSummary(
            tool="API Tester",
            target=data.get("target", "Unknown"),
            timestamp=data.get("timestamp", ""),
            stats=summary_data,
            raw=data,
        )
        for f in data.get("findings", []):
            finding = self._finding_from_dict(f)
            cvss = CVSSCalculator.estimate_for_finding(f)
            finding.cvss = cvss
            scan.findings.append(finding)
            self.all_findings.append(finding)
            self.severity_counts[finding.severity] = self.severity_counts.get(finding.severity, 0) + 1
        self.scans.append(scan)

    def _parse_generic(self, data: dict) -> None:
        scan = ScanSummary(
            tool=data.get("tool", "Unknown"),
            target=data.get("target", data.get("domain", "Unknown")),
            timestamp=data.get("timestamp", ""),
            stats=data.get("summary", {}),
            raw=data,
        )
        for f in data.get("findings", []):
            finding = self._finding_from_dict(f)
            cvss = CVSSCalculator.estimate_for_finding(f)
            finding.cvss = cvss
            scan.findings.append(finding)
            self.all_findings.append(finding)
            self.severity_counts[finding.severity] = self.severity_counts.get(finding.severity, 0) + 1
        self.scans.append(scan)

    @staticmethod
    def _finding_from_dict(d: dict) -> Finding:
        return Finding(
            vuln_type=d.get("vuln_type", d.get("type", "Unknown")),
            severity=d.get("severity", "info"),
            url=d.get("url", d.get("endpoint", "")),
            description=d.get("description", ""),
            remediation=d.get("remediation", ""),
            evidence=d.get("evidence", ""),
            parameter=d.get("parameter", ""),
            payload=d.get("payload", ""),
            method=d.get("method", d.get("request_method", "")),
            endpoint=d.get("endpoint", ""),
            response_code=d.get("response_code", 0),
            response_time=d.get("response_time", 0.0),
        )

    def build_context(self) -> dict[str, Any]:
        targets = []
        total_duration = 0.0
        total_errors = 0

        for scan in self.scans:
            targets.append(scan.target)
            total_duration += scan.stats.get("duration_seconds", 0)
            total_errors += scan.stats.get("errors", 0)

        severity_chart = []
        for sev in SEVERITY_ORDER:
            count = self.severity_counts.get(sev, 0)
            severity_chart.append({"severity": sev, "count": count, "color": SEVERITY_COLORS[sev]})

        max_count = max((item["count"] for item in severity_chart), default=1) or 1
        for item in severity_chart:
            item["width_pct"] = round(item["count"] / max_count * 100, 1)

        # Pre-compute conic-gradient for the pie chart
        total_findings = len(self.all_findings)
        angle = 0
        gradient_parts = []
        for item in severity_chart:
            if item["count"] > 0:
                slice_deg = round(item["count"] / total_findings * 360, 1) if total_findings > 0 else 0
                gradient_parts.append(f"{item['color']} {angle}deg {angle + slice_deg}deg")
                angle += slice_deg
        gradient_parts.append(f"#f3f4f6 {angle}deg 360deg")
        conic_gradient = ", ".join(gradient_parts)

        findings_by_severity = {s: [] for s in SEVERITY_ORDER}
        for f in self.all_findings:
            findings_by_severity[f.severity].append(f)

        targets_str = ", ".join(dict.fromkeys(targets)) or "N/A"

        return {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "targets": targets_str,
            "scans": self.scans,
            "all_findings": self.all_findings,
            "findings_by_severity": findings_by_severity,
            "severity_counts": self.severity_counts,
            "severity_chart": severity_chart,
            "total_findings": len(self.all_findings),
            "total_duration": round(total_duration, 1),
            "total_errors": total_errors,
            "total_scans": len(self.scans),
            "severity_order": SEVERITY_ORDER,
            "severity_colors": SEVERITY_COLORS,
            "severity_bg": SEVERITY_BG,
            "conic_gradient": conic_gradient,
        }


# ---------------------------------------------------------------------------
# HTML Report Template
# ---------------------------------------------------------------------------

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Assessment Report — {{ targets }}</title>
<style>
:root {
    --critical: #dc2626;
    --high: #ea580c;
    --medium: #d97706;
    --low: #2563eb;
    --info: #6b7280;
    --bg: #ffffff;
    --fg: #111827;
    --border: #e5e7eb;
    --surface: #f9fafb;
    --radius: 8px;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: var(--surface);
    color: var(--fg);
    line-height: 1.6;
    padding: 0;
}

.container { max-width: 1100px; margin: 0 auto; padding: 24px 16px; }

/* Header */
.report-header {
    background: linear-gradient(135deg, #1e293b, #334155);
    color: #fff;
    padding: 40px 32px;
    border-radius: var(--radius);
    margin-bottom: 24px;
}
.report-header h1 { font-size: 1.75rem; margin-bottom: 8px; }
.report-header .meta { opacity: 0.85; font-size: 0.9rem; }
.report-header .meta span { margin-right: 20px; }

/* Executive summary */
.exec-summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}
.stat-card {
    background: #fff;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px;
    text-align: center;
}
.stat-card .number { font-size: 2rem; font-weight: 700; }
.stat-card .label { font-size: 0.85rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }
.stat-card.critical .number { color: var(--critical); }
.stat-card.high .number { color: var(--high); }
.stat-card.medium .number { color: var(--medium); }
.stat-card.low .number { color: var(--low); }
.stat-card.info .number { color: var(--info); }

/* Severity chart */
.chart-section {
    background: #fff;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px;
    margin-bottom: 24px;
}
.chart-section h2 { font-size: 1.15rem; margin-bottom: 16px; }
.chart-bar-row {
    display: flex;
    align-items: center;
    margin-bottom: 8px;
}
.chart-bar-label {
    width: 80px;
    font-size: 0.85rem;
    font-weight: 600;
    text-transform: capitalize;
}
.chart-bar-track {
    flex: 1;
    height: 24px;
    background: var(--surface);
    border-radius: 4px;
    overflow: hidden;
}
.chart-bar-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.3s;
}
.chart-bar-count {
    width: 40px;
    text-align: right;
    font-size: 0.85rem;
    font-weight: 600;
    margin-left: 8px;
}

/* Sections */
.section {
    background: #fff;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 24px;
    overflow: hidden;
}
.section-header {
    padding: 16px 24px;
    border-bottom: 1px solid var(--border);
    font-size: 1.15rem;
    font-weight: 600;
    background: var(--surface);
}
.section-body { padding: 24px; }

/* Findings table */
.findings-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
}
.findings-table th {
    text-align: left;
    padding: 10px 12px;
    border-bottom: 2px solid var(--border);
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #6b7280;
}
.findings-table td {
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}
.findings-table tr:last-child td { border-bottom: none; }
.findings-table tr:hover { background: var(--surface); }

.severity-badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    color: #fff;
}
.severity-badge.critical { background: var(--critical); }
.severity-badge.high { background: var(--high); }
.severity-badge.medium { background: var(--medium); }
.severity-badge.low { background: var(--low); }
.severity-badge.info { background: var(--info); }

.cvss-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
}

/* Finding detail card */
.finding-card {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 16px;
    overflow: hidden;
}
.finding-card-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
}
.finding-card-body { padding: 16px; }
.finding-card-body h4 { font-size: 0.85rem; color: #6b7280; margin-bottom: 4px; }
.finding-card-body p { margin-bottom: 12px; }
.finding-card-body pre {
    background: #1e293b;
    color: #e2e8f0;
    padding: 12px;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 0.82rem;
    line-height: 1.5;
}

/* Recon section */
.recon-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 16px;
}
.recon-card {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px;
}
.recon-card h3 { font-size: 0.95rem; margin-bottom: 8px; }
.recon-card ul { list-style: none; padding: 0; }
.recon-card li { padding: 4px 0; font-size: 0.85rem; }
.recon-card li::before { content: "›"; margin-right: 8px; color: #9ca3af; }

/* Footer */
.report-footer {
    text-align: center;
    padding: 24px;
    font-size: 0.8rem;
    color: #9ca3af;
}

/* Print */
@media print {
    body { background: #fff; padding: 0; }
    .container { padding: 0; max-width: 100%; }
    .section { break-inside: avoid; border: 1px solid #ddd; }
    .report-header { background: #1e293b; }
}

/* Responsive */
@media (max-width: 640px) {
    .report-header { padding: 24px 16px; }
    .report-header h1 { font-size: 1.3rem; }
    .exec-summary { grid-template-columns: repeat(2, 1fr); }
    .stat-card .number { font-size: 1.5rem; }
    .findings-table { font-size: 0.8rem; }
    .findings-table th, .findings-table td { padding: 8px 6px; }
    .chart-bar-label { width: 60px; }
}
</style>
</head>
<body>

<div class="container">

<!-- Header -->
<div class="report-header">
    <h1>Security Assessment Report</h1>
    <div class="meta">
        <span><strong>Targets:</strong> {{ targets }}</span>
        <span><strong>Generated:</strong> {{ generated_at }}</span>
        <span><strong>Scans:</strong> {{ total_scans }}</span>
    </div>
</div>

<!-- Executive Summary -->
<div class="exec-summary">
    <div class="stat-card">
        <div class="number">{{ total_findings }}</div>
        <div class="label">Total Findings</div>
    </div>
    <div class="stat-card critical">
        <div class="number">{{ severity_counts.critical }}</div>
        <div class="label">Critical</div>
    </div>
    <div class="stat-card high">
        <div class="number">{{ severity_counts.high }}</div>
        <div class="label">High</div>
    </div>
    <div class="stat-card medium">
        <div class="number">{{ severity_counts.medium }}</div>
        <div class="label">Medium</div>
    </div>
    <div class="stat-card low">
        <div class="number">{{ severity_counts.low }}</div>
        <div class="label">Low</div>
    </div>
    <div class="stat-card info">
        <div class="number">{{ severity_counts.info }}</div>
        <div class="label">Info</div>
    </div>
</div>

<!-- Severity Chart -->
<div class="chart-section">
    <h2>Severity Distribution</h2>
    {% for item in severity_chart %}
    <div class="chart-bar-row">
        <span class="chart-bar-label">{{ item.severity }}</span>
        <div class="chart-bar-track">
            <div class="chart-bar-fill" style="width: {{ item.width_pct }}%; background: {{ item.color }};"></div>
        </div>
        <span class="chart-bar-count">{{ item.count }}</span>
    </div>
    {% endfor %}
</div>

<!-- Severity Breakdown Pie-like CSS chart -->
<div class="chart-section">
    <h2>Findings Overview</h2>
    <div style="display:flex;flex-wrap:wrap;gap:24px;align-items:center;">
        <div style="width:180px;height:180px;border-radius:50%;position:relative;
            background: conic-gradient({{ conic_gradient }});">
            <div style="position:absolute;inset:30px;background:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-direction:column;">
                <span style="font-size:1.5rem;font-weight:700;">{{ total_findings }}</span>
                <span style="font-size:0.75rem;color:#6b7280;">findings</span>
            </div>
        </div>
        <div>
            {% for item in severity_chart %}
            {% if item.count > 0 %}
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
                <span style="width:14px;height:14px;border-radius:3px;background:{{ item.color }};flex-shrink:0;"></span>
                <span style="font-size:0.85rem;">{{ item.severity | capitalize }}: {{ item.count }} ({{ (item.count / total_findings * 100) | round(1) if total_findings > 0 else 0 }}%)</span>
            </div>
            {% endif %}
            {% endfor %}
        </div>
    </div>
</div>

<!-- Recon Section -->
{% for scan in scans %}
{% if scan.tool == "Recon" %}
<div class="section">
    <div class="section-header">Reconnaissance — {{ scan.target }}</div>
    <div class="section-body">
        <div class="recon-grid">
            <div class="recon-card">
                <h3>Subdomains ({{ scan.raw.subdomains | length }})</h3>
                <ul>
                {% for sub in scan.raw.subdomains[:30] %}
                    <li>{{ sub }}</li>
                {% endfor %}
                {% if scan.raw.subdomains | length > 30 %}
                    <li><em>... and {{ scan.raw.subdomains | length - 30 }} more</em></li>
                {% endif %}
                </ul>
            </div>
            <div class="recon-card">
                <h3>Open Ports</h3>
                {% for host, ports in scan.raw.ports.items() %}
                <p><strong>{{ host }}</strong></p>
                <ul>
                {% for p in ports %}
                    <li>{{ p.port }}/{{ p.protocol }} — {{ p.service }}{% if p.version %} ({{ p.version }}){% endif %}</li>
                {% endfor %}
                </ul>
                {% endfor %}
                {% if not scan.raw.ports %}
                <p style="color:#9ca3af;">No open ports found</p>
                {% endif %}
            </div>
            <div class="recon-card">
                <h3>Technologies</h3>
                <ul>
                {% for tech in scan.stats.technologies_detected | default([]) %}
                    <li>{{ tech }}</li>
                {% else %}
                    <li style="color:#9ca3af;">None detected</li>
                {% endfor %}
                </ul>
            </div>
            <div class="recon-card">
                <h3>Statistics</h3>
                <ul>
                    <li>Subdomains found: {{ scan.stats.subdomains_found | default(0) }}</li>
                    <li>Hosts with open ports: {{ scan.stats.hosts_with_open_ports | default(0) }}</li>
                    <li>Total open ports: {{ scan.stats.total_open_ports | default(0) }}</li>
                    <li>Duration: {{ scan.stats.duration_seconds | default(0) }}s</li>
                </ul>
            </div>
        </div>
    </div>
</div>
{% endif %}
{% endfor %}

<!-- Detailed Findings Table -->
{% if all_findings %}
<div class="section">
    <div class="section-header">Detailed Findings</div>
    <div class="section-body" style="overflow-x:auto;">
        <table class="findings-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>CVSS</th>
                    <th>URL / Endpoint</th>
                    <th>Source</th>
                </tr>
            </thead>
            <tbody>
            {% for f in all_findings %}
                <tr>
                    <td>{{ loop.index }}</td>
                    <td><span class="severity-badge {{ f.severity }}">{{ f.severity }}</span></td>
                    <td>{{ f.vuln_type }}</td>
                    <td>
                        {% if f.cvss %}
                        <span class="cvss-badge" style="background:{{ severity_colors[f.cvss.rating | lower] if f.cvss.rating | lower in severity_colors else '#6b7280' }};color:#fff;">{{ f.cvss.score }}</span>
                        {% else %}
                        —
                        {% endif %}
                    </td>
                    <td style="max-width:280px;word-break:break-all;font-size:0.82rem;">{{ f.url }}</td>
                    <td>{{ f.method or '' }}</td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- Findings by Severity -->
{% for sev in severity_order %}
{% if findings_by_severity[sev] %}
<div class="section">
    <div class="section-header" style="border-left:4px solid {{ severity_colors[sev] }};">
        {{ sev | capitalize }} Findings ({{ findings_by_severity[sev] | length }})
    </div>
    <div class="section-body">
        {% for f in findings_by_severity[sev] %}
        <div class="finding-card" style="border-left:3px solid {{ severity_colors[sev] }};">
            <div class="finding-card-header">
                <span class="severity-badge {{ f.severity }}">{{ f.severity }}</span>
                <strong>{{ f.vuln_type }}</strong>
                {% if f.cvss %}
                <span class="cvss-badge" style="background:{{ severity_colors[f.cvss.rating | lower] if f.cvss.rating | lower in severity_colors else '#6b7280' }};color:#fff;margin-left:auto;">CVSS {{ f.cvss.score }} ({{ f.cvss.rating }})</span>
                {% endif %}
            </div>
            <div class="finding-card-body">
                <p>{{ f.description }}</p>
                {% if f.url %}
                <h4>Affected URL</h4>
                <p style="font-family:monospace;font-size:0.85rem;">{{ f.method }} {{ f.url }}</p>
                {% endif %}
                {% if f.parameter %}
                <h4>Parameter</h4>
                <p><code>{{ f.parameter }}</code></p>
                {% endif %}
                {% if f.payload %}
                <h4>Payload</h4>
                <pre>{{ f.payload }}</pre>
                {% endif %}
                {% if f.evidence %}
                <h4>Evidence</h4>
                <pre>{{ f.evidence }}</pre>
                {% endif %}
                {% if f.cvss and f.cvss.vector != "N/A" %}
                <h4>CVSS Vector</h4>
                <p style="font-family:monospace;font-size:0.82rem;">{{ f.cvss.vector }}</p>
                {% endif %}
                {% if f.remediation %}
                <h4>Remediation</h4>
                <p>{{ f.remediation }}</p>
                {% endif %}
            </div>
        </div>
        {% endfor %}
    </div>
</div>
{% endif %}
{% endfor %}
{% endif %}

<!-- Scan Details -->
{% for scan in scans %}
{% if scan.tool != "Recon" %}
<div class="section">
    <div class="section-header">{{ scan.tool }} — {{ scan.target }}</div>
    <div class="section-body">
        <div style="display:flex;flex-wrap:wrap;gap:16px;margin-bottom:16px;">
            <div><strong>Target:</strong> {{ scan.target }}</div>
            <div><strong>Tool:</strong> {{ scan.tool }}</div>
            {% if scan.stats.duration_seconds is defined %}
            <div><strong>Duration:</strong> {{ scan.stats.duration_seconds }}s</div>
            {% endif %}
            {% if scan.stats.tests_run is defined %}
            <div><strong>Tests run:</strong> {{ scan.stats.tests_run | length }} categories</div>
            {% endif %}
        </div>
        {% if scan.stats %}
        <h4 style="margin-bottom:8px;">Scan Summary</h4>
        <table class="findings-table">
            <tbody>
            {% for key, value in scan.stats.items() %}
                {% if key != "tests_run" %}
                <tr><td style="font-weight:600;">{{ key | replace('_', ' ') | capitalize }}</td><td>{{ value }}</td></tr>
                {% endif %}
            {% endfor %}
            {% if scan.stats.tests_run is defined %}
            <tr><td style="font-weight:600;">Tests Run</td><td>
                {% for test_name, count in scan.stats.tests_run.items() %}
                    {{ test_name | replace('_', ' ') | capitalize }}: {{ count }}{% if not loop.last %}, {% endif %}
                {% endfor %}
            </td></tr>
            {% endif %}
            </tbody>
        </table>
        {% endif %}
    </div>
</div>
{% endif %}
{% endfor %}

<!-- Footer -->
<div class="report-footer">
    <p>Report generated by Security Assessment Report Generator</p>
    <p>{{ generated_at }}</p>
</div>

</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Output generators
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Produces reports in various formats."""

    def __init__(self, context: dict[str, Any]):
        self.ctx = context

    def html(self) -> str:
        try:
            from jinja2 import Template
            template = Template(HTML_TEMPLATE)
            return template.render(**self.ctx)
        except ImportError:
            return self._html_fallback()

    def _html_fallback(self) -> str:
        """Minimal HTML without Jinja2 for environments where it's unavailable."""
        ctx = self.ctx
        rows = ""
        for i, f in enumerate(ctx["all_findings"], 1):
            badge_class = f.severity
            cvss_str = f"CVSS {f.cvss.score}" if f.cvss else "—"
            rows += (
                f'<tr><td>{i}</td>'
                f'<td><span class="severity-badge {badge_class}">{f.severity}</span></td>'
                f'<td>{f.vuln_type}</td><td>{cvss_str}</td>'
                f'<td>{f.url}</td></tr>\n'
            )

        severity_bars = ""
        for item in ctx["severity_chart"]:
            severity_bars += (
                f'<div class="chart-bar-row">'
                f'<span class="chart-bar-label">{item["severity"]}</span>'
                f'<div class="chart-bar-track"><div class="chart-bar-fill" '
                f'style="width:{item["width_pct"]}%;background:{item["color"]};"></div></div>'
                f'<span class="chart-bar-count">{item["count"]}</span></div>\n'
            )

        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report</title></head><body style="font-family:sans-serif;padding:20px;max-width:1000px;margin:0 auto;">
<h1>Security Assessment Report</h1>
<p><strong>Targets:</strong> {ctx['targets']} | <strong>Generated:</strong> {ctx['generated_at']}</p>
<div style="display:flex;gap:16px;flex-wrap:wrap;margin:16px 0;">
<div style="text-align:center;"><strong style="font-size:2rem;">{ctx['total_findings']}</strong><br>Total</div>
{"".join(f'<div style="text-align:center;"><strong style="font-size:2rem;color:{SEVERITY_COLORS[s]};">{ctx["severity_counts"][s]}</strong><br>{s.capitalize()}</div>' for s in SEVERITY_ORDER)}
</div>
<h2>Severity Distribution</h2>{severity_bars}
<h2>Findings</h2>
<table style="width:100%;border-collapse:collapse;">
<tr style="border-bottom:2px solid #ccc;"><th style="text-align:left;padding:8px;">#</th><th style="text-align:left;padding:8px;">Severity</th><th style="text-align:left;padding:8px;">Type</th><th style="text-align:left;padding:8px;">CVSS</th><th style="text-align:left;padding:8px;">URL</th></tr>
{rows}</table>
<p style="margin-top:24px;color:#888;font-size:0.8rem;">Generated by Security Assessment Report Generator — {ctx['generated_at']}</p>
</body></html>"""

    def markdown(self) -> str:
        lines = [
            f"# Security Assessment Report\n",
            f"**Targets:** {self.ctx['targets']}  ",
            f"**Generated:** {self.ctx['generated_at']}  ",
            f"**Total Scans:** {self.ctx['total_scans']}  ",
            f"**Total Findings:** {self.ctx['total_findings']}\n",
            "---\n",
            "## Executive Summary\n",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for s in SEVERITY_ORDER:
            lines.append(f"| {s.capitalize()} | {self.ctx['severity_counts'][s]} |")

        lines.append(f"\n**Total Duration:** {self.ctx['total_duration']}s  ")
        lines.append(f"**Errors:** {self.ctx['total_errors']}\n")

        lines.append("---\n## Severity Distribution\n")
        for item in self.ctx["severity_chart"]:
            bar_len = item["count"]
            lines.append(f"- **{item['severity'].capitalize()}:** {'█' * bar_len} ({item['count']})")
        lines.append("")

        if self.ctx["all_findings"]:
            lines.append("---\n## Detailed Findings\n")
            lines.append("| # | Severity | Type | CVSS | URL | Method |")
            lines.append("|---|----------|------|------|-----|--------|")
            for i, f in enumerate(self.ctx["all_findings"], 1):
                cvss_str = f"{f.cvss.score}" if f.cvss else "—"
                lines.append(f"| {i} | {f.severity} | {f.vuln_type} | {cvss_str} | {f.url} | {f.method} |")

            lines.append("")
            lines.append("---\n## Findings Detail\n")
            for sev in SEVERITY_ORDER:
                findings = self.ctx["findings_by_severity"][sev]
                if findings:
                    lines.append(f"### {sev.capitalize()} Findings\n")
                    for f in findings:
                        lines.append(f"#### {f.vuln_type}\n")
                        lines.append(f"- **Severity:** {f.severity}")
                        if f.cvss:
                            lines.append(f"- **CVSS:** {f.cvss.score} ({f.cvss.rating})")
                            if f.cvss.vector != "N/A":
                                lines.append(f"- **Vector:** `{f.cvss.vector}`")
                        lines.append(f"- **URL:** `{f.method} {f.url}`")
                        if f.parameter:
                            lines.append(f"- **Parameter:** `{f.parameter}`")
                        if f.payload:
                            lines.append(f"- **Payload:** `{f.payload}`")
                        if f.evidence:
                            lines.append(f"- **Evidence:** `{f.evidence}`")
                        lines.append(f"\n**Description:** {f.description}\n")
                        if f.remediation:
                            lines.append(f"**Remediation:** {f.remediation}\n")
                        lines.append("---\n")

        lines.append(f"\n*Report generated by Security Assessment Report Generator — {self.ctx['generated_at']}*")
        return "\n".join(lines)

    def json(self) -> str:
        output = {
            "generated_at": self.ctx["generated_at"],
            "targets": self.ctx["targets"],
            "total_findings": self.ctx["total_findings"],
            "total_scans": self.ctx["total_scans"],
            "severity_summary": self.ctx["severity_counts"],
            "findings": [],
        }
        for f in self.ctx["all_findings"]:
            entry = {
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "url": f.url,
                "method": f.method,
                "parameter": f.parameter,
                "description": f.description,
                "remediation": f.remediation,
                "evidence": f.evidence,
                "payload": f.payload,
                "response_code": f.response_code,
                "response_time": f.response_time,
            }
            if f.cvss:
                entry["cvss"] = {"score": f.cvss.score, "rating": f.cvss.rating, "vector": f.cvss.vector}
            output["findings"].append(entry)
        return json.dumps(output, indent=2)

    def pdf(self) -> bytes | None:
        """Generate PDF via weasyprint if available. Returns bytes or None."""
        try:
            from weasyprint import HTML as WeasyHTML
            html_content = self.html()
            return WeasyHTML(string=html_content).write_pdf()
        except ImportError:
            print("[!] weasyprint not installed. Install with: pip install weasyprint", file=sys.stderr)
            return None
        except Exception as exc:
            print(f"[!] PDF generation failed: {exc}", file=sys.stderr)
            return None

    def save(self, output_path: str, fmt: str) -> str:
        ext_map = {"html": ".html", "json": ".json", "markdown": ".md", "md": ".md", "pdf": ".pdf"}
        ext = ext_map.get(fmt, ".html")

        base = Path(output_path)
        if base.suffix.lower() in ext_map.values():
            base = base.with_suffix(ext)
        else:
            base = base.with_suffix(ext)

        base.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "html":
            content = self.html()
            base.write_text(content, encoding="utf-8")
        elif fmt in ("markdown", "md"):
            content = self.markdown()
            base.write_text(content, encoding="utf-8")
        elif fmt == "json":
            content = self.json()
            base.write_text(content, encoding="utf-8")
        elif fmt == "pdf":
            pdf_bytes = self.pdf()
            if pdf_bytes:
                base.write_bytes(pdf_bytes)
            else:
                print("[!] Falling back to HTML output.", file=sys.stderr)
                base = base.with_suffix(".html")
                base.write_text(self.html(), encoding="utf-8")
        else:
            content = self.html()
            base.write_text(content, encoding="utf-8")

        return str(base)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Security Assessment Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python report_generator.py recon.json web_scanner.json --format html\n"
            "  python report_generator.py *.json --format markdown -o report.md\n"
            "  python report_generator.py scan.json --format pdf -o report.pdf\n"
            "  python report_generator.py scan.json --format json -o report.json\n"
        ),
    )
    parser.add_argument(
        "input_files",
        nargs="+",
        help="JSON result files from recon, web_scanner, or api_tester",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["html", "json", "markdown", "md", "pdf"],
        default="html",
        help="Output format (default: html)",
    )
    parser.add_argument(
        "-o", "--output",
        default="report",
        help="Output file path or base name (default: report)",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.input_files:
        parser.print_help()
        sys.exit(1)

    builder = ReportBuilder()
    for fpath in args.input_files:
        if not os.path.isfile(fpath):
            print(f"[!] File not found: {fpath}", file=sys.stderr)
            continue
        builder.add_json_file(fpath)

    if not builder.scans:
        print("[!] No valid scan data loaded. Exiting.", file=sys.stderr)
        sys.exit(1)

    context = builder.build_context()
    generator = ReportGenerator(context)
    out_path = generator.save(args.output, args.format)
    print(f"[+] Report saved to: {out_path}")


if __name__ == "__main__":
    main()
