#!/usr/bin/env python3
"""
Cybersecurity Lab - Unified CLI Entry Point
============================================

Provides a single interface to all security assessment tools:
  - recon: Domain reconnaissance (subdomains, ports, tech fingerprinting)
  - web_scanner: Web vulnerability scanning (XSS, SQLi, CSRF, headers)
  - api_tester: API security testing (auth, IDOR, rate limiting, input validation)
  - report_generator: Aggregated security reports (HTML, JSON, Markdown, PDF)

Usage:
  python cybersec.py scan --target example.com
  python cybersec.py recon --domain example.com
  python cybersec.py web --target http://example.com
  python cybersec.py api --target http://example.com/api
  python cybersec.py report file1.json file2.json -f html
"""

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path
from datetime import datetime

# Ensure tools/ is importable
TOOLS_DIR = Path(__file__).resolve().parent / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


# ── Terminal Colors ──────────────────────────────────────────────────────────

class Colors:
    """ANSI color codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


def supports_color():
    """Check if the terminal supports color output."""
    if os.getenv("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    return True

USE_COLOR = supports_color()


def c(text, color):
    """Wrap text in ANSI color codes if supported."""
    if USE_COLOR:
        return f"{color}{text}{Colors.RESET}"
    return text


# ── Progress Display ─────────────────────────────────────────────────────────

def print_banner():
    """Print the application banner."""
    banner = f"""
{c('╔══════════════════════════════════════════════════════════════╗', Colors.CYAN)}
{c('║', Colors.CYAN)}  {c('Cybersecurity Lab', Colors.BOLD + Colors.WHITE)}  {c('─', Colors.DIM)}  {c('Unified Security Assessment Toolkit', Colors.DIM)}     {c('║', Colors.CYAN)}
{c('╚══════════════════════════════════════════════════════════════╝', Colors.CYAN)}
"""
    print(banner)


def print_section(title):
    """Print a styled section header."""
    print(f"\n{c('┌─ ', Colors.CYAN)}{c(title, Colors.BOLD)}")
    print(f"{c('│', Colors.CYAN)}")


def print_step(message, status="info"):
    """Print a step with status indicator."""
    icons = {
        "info":    c("●", Colors.BLUE),
        "running": c("◉", Colors.YELLOW),
        "ok":      c("✔", Colors.GREEN),
        "warn":    c("▲", Colors.YELLOW),
        "error":   c("✖", Colors.RED),
        "skip":    c("○", Colors.DIM),
    }
    icon = icons.get(status, icons["info"])
    print(f"{c('│', Colors.CYAN)}  {icon}  {message}")


def print_section_end():
    """Close a section block."""
    print(f"{c('└─', Colors.CYAN)}")


def print_summary_table(rows):
    """Print a key-value summary table."""
    if not rows:
        return
    max_key = max(len(k) for k, _ in rows)
    print(f"{c('│', Colors.CYAN)}")
    for key, value in rows:
        print(f"{c('│', Colors.CYAN)}  {c(key.ljust(max_key), Colors.DIM)}  {value}")
    print(f"{c('└─', Colors.CYAN)}")


def run_with_progress(coro, description):
    """Run an async coroutine with a progress spinner."""
    print_step(description, "running")
    start = time.time()
    try:
        result = asyncio.run(coro)
        elapsed = time.time() - start
        print_step(f"Completed in {c(f'{elapsed:.1f}s', Colors.GREEN)}", "ok")
        return result
    except Exception as e:
        elapsed = time.time() - start
        print_step(f"Failed after {c(f'{elapsed:.1f}s', Colors.RED)}: {e}", "error")
        return None


# ── Tool Runners ─────────────────────────────────────────────────────────────

async def run_recon(domain, output, verbose=False, **kwargs):
    """Run domain reconnaissance."""
    from recon import ReconTool
    tool = ReconTool(
        domain=domain,
        output=output,
        ports=kwargs.get("ports", "1-1000"),
    )
    if verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)
    return await tool.run()


async def run_web_scanner(target, output, verbose=False, **kwargs):
    """Run web vulnerability scanner."""
    from web_scanner import WebVulnerabilityScanner
    tool = WebVulnerabilityScanner(
        target=target,
        output=output,
        rate_limit=kwargs.get("rate_limit", 10.0),
        max_depth=kwargs.get("max_depth", 2),
        max_pages=kwargs.get("max_pages", 50),
        timeout=kwargs.get("timeout", 15),
        headers_only=kwargs.get("headers_only", False),
    )
    if verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)
    return await tool.run()


async def run_api_tester(target, output, verbose=False, **kwargs):
    """Run API security tester."""
    from api_tester import APISecurityTester
    tool = APISecurityTester(
        target=target,
        output=output,
        rate_limit=kwargs.get("rate_limit", 5.0),
        timeout=kwargs.get("timeout", 15),
        spec_url=kwargs.get("spec_url"),
        token=kwargs.get("token"),
        api_type=kwargs.get("api_type", "auto"),
    )
    if verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)
    return await tool.run()


def run_report(input_files, output, fmt="html"):
    """Run report generator."""
    from report_generator import main as report_main
    sys.argv = [
        "report_generator",
        *input_files,
        "-f", fmt,
        "-o", output,
    ]
    report_main()


# ── Subcommand Handlers ──────────────────────────────────────────────────────

def cmd_recon(args):
    """Handle the 'recon' subcommand."""
    print_section("Domain Reconnaissance")
    output = args.output or f"reports/recon_{args.domain}_{int(time.time())}.json"
    Path(output).parent.mkdir(parents=True, exist_ok=True)

    result = run_with_progress(
        run_recon(args.domain, output, verbose=args.verbose, ports=args.ports),
        f"Scanning {c(args.domain, Colors.WHITE)}"
    )

    if result:
        subs = len(result.get("subdomains", []))
        ports = len(result.get("open_ports", []))
        techs = len(result.get("technologies", []))
        print_summary_table([
            ("Domain",    c(args.domain, Colors.WHITE)),
            ("Subdomains", c(str(subs), Colors.GREEN)),
            ("Open Ports", c(str(ports), Colors.GREEN)),
            ("Technologies", c(str(techs), Colors.GREEN)),
            ("Output",    c(output, Colors.CYAN)),
        ])
    print_section_end()
    return 0 if result else 1


def cmd_web(args):
    """Handle the 'web' subcommand."""
    print_section("Web Vulnerability Scanner")
    output = args.output or f"reports/web_{_slug(args.target)}_{int(time.time())}.json"
    Path(output).parent.mkdir(parents=True, exist_ok=True)

    result = run_with_progress(
        run_web_scanner(
            args.target, output, verbose=args.verbose,
            max_depth=args.depth, max_pages=args.max_pages,
            rate_limit=args.rate, timeout=args.timeout,
            headers_only=args.headers_only,
        ),
        f"Scanning {c(args.target, Colors.WHITE)}"
    )

    if result:
        summary = result.get("summary", {})
        print_summary_table([
            ("Target",   c(args.target, Colors.WHITE)),
            ("Findings", c(str(summary.get("total_findings", 0)), Colors.YELLOW)),
            ("Critical", c(str(summary.get("critical", 0)), Colors.BG_RED + Colors.WHITE)),
            ("High",     c(str(summary.get("high", 0)), Colors.RED)),
            ("Medium",   c(str(summary.get("medium", 0)), Colors.YELLOW)),
            ("Low",      c(str(summary.get("low", 0)), Colors.BLUE)),
            ("Output",   c(output, Colors.CYAN)),
        ])
    print_section_end()
    return 0 if result else 1


def cmd_api(args):
    """Handle the 'api' subcommand."""
    print_section("API Security Tester")
    output = args.output or f"reports/api_{_slug(args.target)}_{int(time.time())}.json"
    Path(output).parent.mkdir(parents=True, exist_ok=True)

    result = run_with_progress(
        run_api_tester(
            args.target, output, verbose=args.verbose,
            rate_limit=args.rate, timeout=args.timeout,
            spec_url=args.spec, token=args.token, api_type=args.type,
        ),
        f"Testing {c(args.target, Colors.WHITE)}"
    )

    if result:
        summary = result.get("summary", {})
        print_summary_table([
            ("Target",   c(args.target, Colors.WHITE)),
            ("API Type", c(result.get("api_type", "unknown"), Colors.MAGENTA)),
            ("Endpoints", c(str(result.get("endpoints_found", 0)), Colors.GREEN)),
            ("Findings", c(str(summary.get("total_findings", 0)), Colors.YELLOW)),
            ("Tests Run", c(str(result.get("tests_run", 0)), Colors.GREEN)),
            ("Output",   c(output, Colors.CYAN)),
        ])
    print_section_end()
    return 0 if result else 1


def cmd_report(args):
    """Handle the 'report' subcommand."""
    print_section("Report Generator")
    output = args.output or f"report_{int(time.time())}"

    try:
        run_report(args.input_files, output, fmt=args.format)
        ext = {"html": ".html", "json": ".json", "markdown": ".md", "pdf": ".pdf"}.get(args.format, "")
        print_step(f"Report generated: {c(output + ext, Colors.CYAN)}", "ok")
        print_section_end()
        return 0
    except Exception as e:
        print_step(f"Report generation failed: {e}", "error")
        print_section_end()
        return 1


def cmd_scan(args):
    """Handle the 'scan' subcommand — full or partial assessment."""
    target = args.target
    output_dir = args.output or "reports"
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = int(time.time())

    # Determine which tools to run
    run_r = args.full_scan or not (args.web_only or args.api_only)
    run_w = args.full_scan or not (args.recon_only or args.api_only)
    run_a = args.full_scan or not (args.recon_only or args.web_only)

    # Shortcut flags override
    if args.recon_only:
        run_r, run_w, run_a = True, False, False
    if args.web_only:
        run_r, run_w, run_a = False, True, False
    if args.api_only:
        run_r, run_w, run_a = False, False, True

    tools_to_run = []
    if run_r: tools_to_run.append("recon")
    if run_w: tools_to_run.append("web_scanner")
    if run_a: tools_to_run.append("api_tester")

    print_section("Full Security Assessment")
    print_step(f"Target:  {c(target, Colors.WHITE)}")
    print_step(f"Output:  {c(output_dir, Colors.CYAN)}")
    print_step(f"Tools:   {c(' → '.join(tools_to_run), Colors.MAGENTA)}")
    print()

    start_time = time.time()
    result_files = []
    all_results = {}

    # ── Recon ──
    if run_r:
        print_section("Phase 1: Domain Reconnaissance")
        recon_out = f"{output_dir}/recon_{_slug(target)}_{timestamp}.json"
        result = run_with_progress(
            run_recon(target, recon_out, verbose=args.verbose, ports=args.ports),
            f"Enumerating subdomains & ports for {c(target, Colors.WHITE)}"
        )
        if result:
            all_results["recon"] = result
            result_files.append(recon_out)
            subs = len(result.get("subdomains", []))
            print_step(f"Found {c(str(subs), Colors.GREEN)} subdomains", "ok")
        else:
            print_step("Recon produced no results", "warn")
        print_section_end()

    # ── Web Scanner ──
    if run_w:
        print_section("Phase 2: Web Vulnerability Scan")
        web_out = f"{output_dir}/web_{_slug(target)}_{timestamp}.json"
        web_target = target if target.startswith("http") else f"https://{target}"
        result = run_with_progress(
            run_web_scanner(
                web_target, web_out, verbose=args.verbose,
                max_depth=args.depth, max_pages=args.max_pages,
                rate_limit=args.rate, timeout=args.timeout,
            ),
            f"Crawling & testing {c(web_target, Colors.WHITE)}"
        )
        if result:
            all_results["web_scanner"] = result
            result_files.append(web_out)
            findings = result.get("summary", {}).get("total_findings", 0)
            print_step(f"Found {c(str(findings), Colors.YELLOW)} vulnerabilities", "ok")
        else:
            print_step("Web scan produced no results", "warn")
        print_section_end()

    # ── API Tester ──
    if run_a:
        print_section("Phase 3: API Security Test")
        api_out = f"{output_dir}/api_{_slug(target)}_{timestamp}.json"
        api_target = target if target.startswith("http") else f"https://{target}"
        result = run_with_progress(
            run_api_tester(
                api_target, api_out, verbose=args.verbose,
                rate_limit=args.rate, timeout=args.timeout,
                spec_url=args.spec, token=args.token, api_type=args.type,
            ),
            f"Testing API endpoints at {c(api_target, Colors.WHITE)}"
        )
        if result:
            all_results["api_tester"] = result
            result_files.append(api_out)
            findings = result.get("summary", {}).get("total_findings", 0)
            print_step(f"Found {c(str(findings), Colors.YELLOW)} issues", "ok")
        else:
            print_step("API test produced no results", "warn")
        print_section_end()

    # ── Report ──
    if result_files:
        print_section("Phase 4: Report Generation")
        report_out = f"{output_dir}/report_{_slug(target)}_{timestamp}"
        try:
            run_report(result_files, report_out, fmt=args.format)
            ext = {"html": ".html", "json": ".json", "markdown": ".md", "pdf": ".pdf"}.get(args.format, "")
            print_step(f"Report saved: {c(report_out + ext, Colors.CYAN)}", "ok")
        except Exception as e:
            print_step(f"Report generation failed: {e}", "error")
        print_section_end()
    else:
        print_step("No results to report", "warn")

    # ── Summary ──
    elapsed = time.time() - start_time
    print_section("Assessment Summary")
    total_findings = 0
    for r in all_results.values():
        total_findings += r.get("summary", {}).get("total_findings", 0)

    print_summary_table([
        ("Target",      c(target, Colors.WHITE)),
        ("Tools Run",   c(str(len(tools_to_run)), Colors.GREEN)),
        ("Findings",    c(str(total_findings), Colors.YELLOW)),
        ("Duration",    c(f"{elapsed:.1f}s", Colors.CYAN)),
        ("Report Dir",  c(output_dir, Colors.CYAN)),
        ("Result Files", c(str(len(result_files)), Colors.GREEN)),
    ])
    print_section_end()

    return 0 if result_files else 1


def _slug(text):
    """Convert text to a filesystem-safe slug."""
    return text.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")[:50]


# ── Argument Parser ──────────────────────────────────────────────────────────

def build_parser():
    """Build the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="cybersec",
        description=c("Cybersecurity Lab — Unified Security Assessment Toolkit", Colors.BOLD),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{c('examples:', Colors.DIM)}
  {c('$', Colors.DIM)} python cybersec.py scan --target example.com
  {c('$', Colors.DIM)} python cybersec.py scan --target 10.0.0.1 --full-scan -f html
  {c('$', Colors.DIM)} python cybersec.py scan --target example.com --recon-only
  {c('$', Colors.DIM)} python cybersec.py scan --target http://example.com --web-only
  {c('$', Colors.DIM)} python cybersec.py scan --target http://api.example.com --api-only
  {c('$', Colors.DIM)} python cybersec.py recon --domain example.com -v
  {c('$', Colors.DIM)} python cybersec.py web --target http://example.com -d 3
  {c('$', Colors.DIM)} python cybersec.py api --target http://api.example.com --spec /openapi.json
  {c('$', Colors.DIM)} python cybersec.py report scan_results/*.json -f html -o report""",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ── scan ──
    p_scan = sub.add_parser("scan", help="Run full or partial security assessment",
                            formatter_class=argparse.RawDescriptionHelpFormatter,
                            description="Execute multiple tools in sequence and generate a combined report.")
    p_scan.add_argument("--target", "-t", required=True, help="Target domain or URL")
    p_scan.add_argument("--output", "-o", help="Output directory (default: reports/)")
    p_scan.add_argument("--format", "-f", default="html",
                        choices=["html", "json", "markdown", "pdf"], help="Report format (default: html)")
    p_scan.add_argument("--full-scan", action="store_true", help="Run all tools (recon + web + api)")
    p_scan.add_argument("--recon-only", action="store_true", help="Run reconnaissance only")
    p_scan.add_argument("--web-only", action="store_true", help="Run web scanner only")
    p_scan.add_argument("--api-only", action="store_true", help="Run API tester only")
    p_scan.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    # recon options
    p_scan.add_argument("--ports", default="1-1000", help="Port range for recon (default: 1-1000)")
    # web options
    p_scan.add_argument("--depth", type=int, default=2, help="Max crawl depth (default: 2)")
    p_scan.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    p_scan.add_argument("--rate", type=float, default=10.0, help="Max concurrent requests (default: 10)")
    p_scan.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    # api options
    p_scan.add_argument("--spec", help="OpenAPI/Swagger spec URL")
    p_scan.add_argument("--token", help="Bearer auth token for API testing")
    p_scan.add_argument("--type", choices=["auto", "rest", "graphql"], default="auto",
                        help="API type (default: auto-detect)")

    # ── recon ──
    p_recon = sub.add_parser("recon", help="Domain reconnaissance (subdomains, ports, tech fingerprinting)")
    p_recon.add_argument("--domain", "-d", required=True, help="Target domain to enumerate")
    p_recon.add_argument("--output", "-o", help="Output JSON file path")
    p_recon.add_argument("--ports", default="1-1000", help="Port range (default: 1-1000)")
    p_recon.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")

    # ── web ──
    p_web = sub.add_parser("web", help="Web vulnerability scanner (XSS, SQLi, CSRF, headers)")
    p_web.add_argument("--target", "-t", required=True, help="Target URL to scan")
    p_web.add_argument("--output", "-o", help="Output JSON file path")
    p_web.add_argument("--depth", "-d", type=int, default=2, help="Max crawl depth (default: 2)")
    p_web.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    p_web.add_argument("--rate", type=float, default=10.0, help="Max concurrent requests (default: 10)")
    p_web.add_argument("--timeout", "-T", type=int, default=15, help="Request timeout (default: 15)")
    p_web.add_argument("--headers-only", action="store_true", help="Only check security headers")
    p_web.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")

    # ── api ──
    p_api = sub.add_parser("api", help="API security tester (auth, IDOR, rate limiting, input validation)")
    p_api.add_argument("--target", "-t", required=True, help="Target API base URL")
    p_api.add_argument("--output", "-o", help="Output JSON file path")
    p_api.add_argument("--spec", help="OpenAPI/Swagger spec URL")
    p_api.add_argument("--token", help="Bearer auth token")
    p_api.add_argument("--type", choices=["auto", "rest", "graphql"], default="auto",
                        help="API type (default: auto-detect)")
    p_api.add_argument("--rate", type=float, default=5.0, help="Max concurrent requests (default: 5)")
    p_api.add_argument("--timeout", "-T", type=int, default=15, help="Request timeout (default: 15)")
    p_api.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")

    # ── report ──
    p_report = sub.add_parser("report", help="Generate report from JSON result files")
    p_report.add_argument("input_files", nargs="+", help="JSON result files to include")
    p_report.add_argument("--format", "-f", default="html",
                          choices=["html", "json", "markdown", "pdf"], help="Report format (default: html)")
    p_report.add_argument("--output", "-o", help="Output file path (default: report)")

    return parser


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if args.no_color:
        global USE_COLOR
        USE_COLOR = False

    if not args.command:
        print_banner()
        parser.print_help()
        return 0

    print_banner()

    commands = {
        "scan":   cmd_scan,
        "recon":  cmd_recon,
        "web":    cmd_web,
        "api":    cmd_api,
        "report": cmd_report,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
