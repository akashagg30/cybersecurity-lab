#!/usr/bin/env python3
"""
API Security Tester - REST & GraphQL API Security Analysis
OpenAPI parsing, auth testing, rate limiting, input validation, mass assignment, IDOR detection.
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
logger = logging.getLogger("api_tester")


# ---------------------------------------------------------------------------
# Constants & Payloads
# ---------------------------------------------------------------------------

AUTH_BYPASS_PAYLOADS = [
    "", "null", "undefined", "false", "0",
    "admin", "guest", "test", "password",
    "Bearer ", "Token ", "Basic Og==",
]

TOKEN_LEAKAGE_HEADERS = [
    "Authorization", "X-Auth-Token", "X-API-Key", "Api-Key",
    "X-Access-Token", "Cookie", "Set-Cookie",
    "WWW-Authenticate", "Proxy-Authenticate", "X-JWT-Token",
]

TOKEN_LEAKAGE_BODY_PATTERNS = [
    r'"token"\s*:\s*"([^"]+)"',
    r'"access_token"\s*:\s*"([^"]+)"',
    r'"jwt"\s*:\s*"([^"]+)"',
    r'"api_key"\s*:\s*"([^"]+)"',
    r'"secret"\s*:\s*"([^"]+)"',
    r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',
    r'eyJ[A-Za-z0-9\-._~+/]+=*',
]

INPUT_VALIDATION_PAYLOADS = {
    "string": [
        "", " ", "  ", "\t", "\n", "\r\n",
        "a" * 10000, "a" * 100000,
        "<script>alert(1)</script>",
        "'; DROP TABLE users;--",
        "../../etc/passwd", "%00", "\x00",
        "-1", "0", "99999999999999999",
        "true", "false", "null", "undefined",
        "1e308", "-1e308", "1e-308",
    ],
    "integer": [
        "-1", "0", "1", "2147483647", "2147483648",
        "-2147483648", "-2147483649", "99999999999999999",
        "0.5", "1.5", "NaN", "Infinity", "-Infinity",
        "", " ", "abc", "null", "true",
    ],
    "number": [
        "-1", "0", "1", "1.7976931348623157e+308",
        "-1.7976931348623157e+308", "1e-308", "-1e-308",
        "NaN", "Infinity", "-Infinity", "", "abc", "null",
    ],
    "boolean": [
        "", "0", "1", "true", "false", "null", "yes", "no",
        "TRUE", "FALSE", "True", "False",
    ],
    "email": [
        "", " ", "a@b", "a@b.c", "test@example.com",
        "test@example.com\nBcc: evil@attacker.com",
        "test@example.com%0d%0aCc:victim@target.com",
        "a" * 1000 + "@example.com",
    ],
    "url": [
        "", " ", "http://", "https://",
        "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd", "http://127.0.0.1:8080",
        "http://[::1]:8080", "http://0x7f000001:8080", "a" * 5000,
    ],
    "date": [
        "", " ", "not-a-date", "2000-01-01", "1970-01-01",
        "9999-12-31", "2000-13-01", "2000-00-01",
        "2000-01-01T99:99:99Z",
    ],
}

MASS_ASSIGNMENT_FIELDS = [
    "role", "admin", "is_admin", "isAdmin", "admin_role",
    "user_type", "type", "account_type", "privilege",
    "permissions", "permission", "access_level",
    "verified", "email_verified", "is_verified",
    "balance", "credit", "credits", "points",
    "id", "user_id", "userId", "account_id",
    "created_at", "updated_at", "created_by", "updated_by",
    "internal", "internal_id", "secret", "api_key",
    "price", "amount", "discount", "cost",
    "is_active", "active", "status", "state",
]

IDOR_ID_PAYLOADS = [
    "1", "2", "3", "100", "101", "999",
    "0", "-1", "admin", "test", "aaaa", "%00", "../1",
]

SECURITY_HEADERS = {
    "Content-Security-Policy": {"severity": "medium", "description": "Missing CSP header"},
    "Strict-Transport-Security": {"severity": "medium", "description": "Missing HSTS header"},
    "X-Content-Type-Options": {"severity": "low", "description": "Missing X-Content-Type-Options"},
    "Cache-Control": {"severity": "low", "description": "Missing Cache-Control on sensitive endpoints"},
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
    endpoint: str = ""
    method: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    response_code: int = 0
    response_time: float = 0.0
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v}


@dataclass
class APIEndpoint:
    path: str
    method: str
    parameters: list = field(default_factory=list)
    request_body: dict = field(default_factory=dict)
    security: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    summary: str = ""
    deprecated: bool = False


@dataclass
class TestResults:
    target: str
    timestamp: str
    api_type: str = "rest"
    endpoints_found: int = 0
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
            "api_type": self.api_type,
            "endpoints_found": self.endpoints_found,
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
# OpenAPI/Swagger Spec Parser
# ---------------------------------------------------------------------------

class OpenAPIParser:
    """Parse OpenAPI 3.x and Swagger 2.0 specifications."""

    SPEC_PATHS = [
        "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
        "/api-docs", "/api-docs.json", "/v1/api-docs", "/v2/api-docs",
        "/docs/openapi.json", "/spec.json", "/swagger.yaml",
        "/openapi.yaml", "/api/swagger.json", "/api/openapi.json",
        "/.well-known/openapi.json",
    ]

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def discover_spec(self, base_url: str) -> Optional[dict]:
        """Try common OpenAPI/Swagger spec locations."""
        base = base_url.rstrip("/")
        for path in self.SPEC_PATHS:
            url = f"{base}{path}"
            try:
                async with self.session.get(
                    url, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        content_type = resp.headers.get("Content-Type", "")
                        if "json" in content_type or "yaml" in content_type:
                            text = await resp.text()
                            try:
                                spec = json.loads(text)
                                if "openapi" in spec or "swagger" in spec:
                                    logger.info(f"Found API spec at {url}")
                                    return spec
                            except json.JSONDecodeError:
                                pass
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
        return None

    def parse_endpoints(self, spec: dict) -> list[APIEndpoint]:
        """Extract endpoints from OpenAPI/Swagger spec."""
        endpoints = []
        is_openapi3 = "openapi" in spec
        paths = spec.get("paths", {})

        for path, methods in paths.items():
            for method in ["get", "post", "put", "patch", "delete", "head", "options"]:
                if method not in methods:
                    continue
                op = methods[method]
                if op.get("deprecated", False):
                    continue

                params = []
                for p in op.get("parameters", []):
                    params.append({
                        "name": p.get("name", ""),
                        "in": p.get("in", "query"),
                        "schema": p.get("schema", {}),
                        "required": p.get("required", False),
                    })

                request_body = {}
                if "requestBody" in op:
                    rb = op["requestBody"]
                    content = rb.get("content", {})
                    for ct, schema in content.items():
                        request_body = {
                            "content_type": ct,
                            "schema": schema.get("schema", {}),
                        }
                        break

                endpoints.append(APIEndpoint(
                    path=path,
                    method=method,
                    parameters=params,
                    request_body=request_body,
                    security=op.get("security", spec.get("security", [])),
                    tags=op.get("tags", []),
                    summary=op.get("summary", ""),
                ))

        logger.info(f"Parsed {len(endpoints)} endpoints from API spec")
        return endpoints

    def _resolve_ref(self, spec: dict, ref: str) -> dict:
        """Resolve a $ref pointer."""
        parts = ref.lstrip("#/").split("/")
        current = spec
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return {}
        return current if isinstance(current, dict) else {}


# ---------------------------------------------------------------------------
# Authentication Tester
# ---------------------------------------------------------------------------

class AuthTester:
    """Test for broken authentication and token leakage."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def _request(
        self, method: str, url: str, headers: dict = None, **kwargs
    ) -> tuple[int, dict, str, float]:
        async with self._semaphore:
            start = time.time()
            try:
                kwargs.setdefault("timeout", aiohttp.ClientTimeout(total=15))
                async with getattr(self.session, method)(
                    url, headers=headers or {}, **kwargs
                ) as resp:
                    body = await resp.text(errors="ignore")
                    resp_headers = dict(resp.headers)
                    return resp.status, resp_headers, body, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, {}, "", time.time() - start

    async def test_broken_auth(
        self, url: str, method: str = "GET", valid_token: str = None
    ) -> list[Finding]:
        """Test for broken authentication by trying various auth bypass payloads."""
        findings = []
        for payload in AUTH_BYPASS_PAYLOADS:
            headers = {"Authorization": payload} if payload else {}
            status, _, body, resp_time = await self._request(method, url, headers=headers)
            if status in (200, 201):
                findings.append(Finding(
                    vuln_type="Broken Authentication",
                    severity=Severity.HIGH,
                    url=url,
                    method=method,
                    payload=payload or "(empty)",
                    evidence=f"HTTP {status} with auth bypass payload",
                    description="Endpoint accessible with missing or empty authentication token.",
                    remediation="Enforce authentication checks on all protected endpoints server-side.",
                    response_code=status,
                ))
        return findings

    async def test_token_leakage(
        self, url: str, method: str = "GET", headers: dict = None
    ) -> list[Finding]:
        """Check responses for token/key leakage in headers and body."""
        findings = []
        status, resp_headers, body, _ = await self._request(method, url, headers=headers)

        for header_name in TOKEN_LEAKAGE_HEADERS:
            if header_name in resp_headers:
                val = resp_headers[header_name]
                if header_name == "Set-Cookie":
                    findings.append(Finding(
                        vuln_type="Token Leakage (Cookie)",
                        severity=Severity.MEDIUM,
                        url=url,
                        header=header_name,
                        evidence=f"Set-Cookie present: {val[:80]}...",
                        description="Tokens exposed in Set-Cookie header. Ensure HttpOnly, Secure, and SameSite flags.",
                        remediation="Set HttpOnly, Secure, and SameSite=Strict on auth cookies.",
                    ))

        for pattern in TOKEN_LEAKAGE_BODY_PATTERNS:
            matches = re.findall(pattern, body)
            if matches:
                findings.append(Finding(
                    vuln_type="Token Leakage (Response Body)",
                    severity=Severity.HIGH,
                    url=url,
                    evidence=f"Token pattern found in response body",
                    description="Sensitive tokens or API keys found in response body.",
                    remediation="Remove tokens from response bodies. Use token introspection instead.",
                    details={"matches": len(matches)},
                ))

        return findings

    async def test_auth_enforcement(
        self, endpoints: list[APIEndpoint], base_url: str
    ) -> list[Finding]:
        """Test authentication enforcement across endpoints."""
        findings = []
        for ep in endpoints:
            if ep.security:
                url = f"{base_url.rstrip('/')}{ep.path}"
                status, _, _, _ = await self._request(ep.method, url)
                if status in (200, 201, 204):
                    findings.append(Finding(
                        vuln_type="Missing Authentication",
                        severity=Severity.CRITICAL,
                        url=url,
                        endpoint=ep.path,
                        method=ep.method,
                        evidence=f"HTTP {status} without authentication",
                        description=f"Secured endpoint {ep.method.upper()} {ep.path} accessible without auth.",
                        remediation="Enforce authentication and authorization for all protected endpoints.",
                        response_code=status,
                    ))
        return findings


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class RateLimitTester:
    """Detect rate limiting on API endpoints."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def _request(self, url: str, headers: dict = None) -> tuple[int, dict, float]:
        async with self._semaphore:
            start = time.time()
            try:
                async with self.session.get(
                    url, headers=headers or {}, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    resp_headers = dict(resp.headers)
                    return resp.status, resp_headers, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, {}, time.time() - start

    async def detect_rate_limiting(
        self, url: str, method: str = "GET", burst_count: int = 20
    ) -> list[Finding]:
        """Send burst requests to detect rate limiting."""
        findings = []
        statuses = []
        has_ratelimit_headers = False

        for _ in range(burst_count):
            status, headers, _ = await self._request(url)
            statuses.append(status)
            if "X-RateLimit-Limit" in headers or "Retry-After" in headers:
                has_ratelimit_headers = True
            await asyncio.sleep(0.05)

        blocked_count = sum(1 for s in statuses if s == 429)
        rate_limited = blocked_count > 0 or has_ratelimit_headers

        if not rate_limited:
            findings.append(Finding(
                vuln_type="Missing Rate Limiting",
                severity=Severity.MEDIUM,
                url=url,
                evidence=f"{burst_count} requests sent, 0 rate-limited (HTTP 429)",
                description="No rate limiting detected. Endpoint vulnerable to brute force and DoS.",
                remediation="Implement rate limiting using token bucket or sliding window algorithms.",
                details={"total_requests": burst_count, "blocked": blocked_count},
            ))
        else:
            findings.append(Finding(
                vuln_type="Rate Limiting Present",
                severity=Severity.INFO,
                url=url,
                evidence=f"{blocked_count}/{burst_count} requests blocked (HTTP 429)",
                description="Rate limiting is active on this endpoint.",
                details={"total_requests": burst_count, "blocked": blocked_count},
            ))

        return findings

    async def test_rate_limit_bypass(
        self, url: str, method: str = "GET"
    ) -> list[Finding]:
        """Try to bypass rate limiting via header manipulation."""
        findings = []
        bypass_headers = [
            {"X-Forwarded-For": "1.2.3.4"},
            {"X-Real-IP": "5.6.7.8"},
            {"X-Originating-IP": "9.10.11.12"},
            {"X-Client-IP": "13.14.15.16"},
            {"X-Forwarded-Host": "different-host.com"},
            {"X-Host": "different-host.com"},
            {"X-Original-URL": "/"},
            {"X-Rewrite-URL": "/"},
            {"CF-Connecting-IP": "17.18.19.20"},
        ]

        for headers in bypass_headers:
            blocked = 0
            for _ in range(5):
                status, _, _ = await self._request(url, headers=headers)
                if status == 429:
                    blocked += 1
                await asyncio.sleep(0.05)

            if blocked == 0:
                finding = Finding(
                    vuln_type="Rate Limit Bypass",
                    severity=Severity.HIGH,
                    url=url,
                    evidence=f"Rate limit bypassed with header: {list(headers.keys())[0]}",
                    description=f"Rate limiting bypassed using {list(headers.keys())[0]} header manipulation.",
                    remediation="Do not rely on client-provided IP headers for rate limiting. Use trusted proxy headers.",
                    details={"bypass_headers": headers},
                )
                findings.append(finding)
                break

        return findings


# ---------------------------------------------------------------------------
# Input Validation Tester
# ---------------------------------------------------------------------------

class InputValidationTester:
    """Test API input validation for injection and edge cases."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def _request(
        self, method: str, url: str, json_data: dict = None,
        params: dict = None, headers: dict = None
    ) -> tuple[int, str, float]:
        async with self._semaphore:
            start = time.time()
            try:
                kwargs = {"timeout": aiohttp.ClientTimeout(total=15)}
                if headers:
                    kwargs["headers"] = headers
                if method.lower() == "get":
                    if params:
                        kwargs["params"] = params
                    async with self.session.get(url, **kwargs) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
                else:
                    if json_data is not None:
                        kwargs["json"] = json_data
                    async with getattr(self.session, method.lower())(url, **kwargs) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, "", time.time() - start

    async def test_endpoint_inputs(
        self, url: str, method: str, parameters: list,
        request_body: dict = None, headers: dict = None
    ) -> list[Finding]:
        """Test input validation for an endpoint's parameters."""
        findings = []

        for param in parameters:
            param_name = param.get("name", "")
            schema = param.get("schema", {})
            param_type = schema.get("type", "string")
            payloads = INPUT_VALIDATION_PAYLOADS.get(param_type, INPUT_VALIDATION_PAYLOADS["string"])

            for payload in payloads[:5]:
                if param.get("in") == "query":
                    status, body, resp_time = await self._request(
                        method, url, params={param_name: payload}, headers=headers
                    )
                elif param.get("in") == "path":
                    test_url = url.replace(f"{{{param_name}}}", str(payload))
                    status, body, resp_time = await self._request(method, test_url, headers=headers)
                else:
                    continue

                if status == 500:
                    findings.append(Finding(
                        vuln_type="Input Validation (500 Error)",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param_name,
                        payload=str(payload)[:200],
                        evidence=f"HTTP 500 with payload: {str(payload)[:100]}",
                        description=f"Server crash on {param_type} input '{param_name}'. Missing input validation.",
                        remediation="Validate all inputs server-side. Return 400 for invalid input, never 500.",
                        response_code=status,
                        response_time=resp_time,
                    ))
                    break

                if "sql" in body.lower() or "syntax error" in body.lower():
                    findings.append(Finding(
                        vuln_type="SQL Injection via Input",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param_name,
                        payload=str(payload)[:200],
                        evidence="SQL error in response",
                        description="SQL error triggered via input parameter.",
                        remediation="Use parameterized queries. Validate and sanitize all inputs.",
                        response_code=status,
                    ))
                    break

        if request_body and method.lower() in ("post", "put", "patch"):
            findings.extend(
                await self._test_body_validation(url, method, request_body, headers)
            )

        return findings

    async def _test_body_validation(
        self, url: str, method: str, request_body: dict, headers: dict = None
    ) -> list[Finding]:
        """Test request body validation."""
        findings = []
        schema = request_body.get("schema", {})
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        if required:
            incomplete = {k: v.get("example", "test") for k, v in properties.items() if k not in required}
            if incomplete:
                status, body, _ = await self._request(method, url, json_data=incomplete, headers=headers)
                if status not in (400, 422):
                    findings.append(Finding(
                        vuln_type="Missing Required Field Validation",
                        severity=Severity.MEDIUM,
                        url=url,
                        evidence=f"HTTP {status} with missing required fields",
                        description="API accepts requests with missing required fields.",
                        remediation="Validate required fields server-side. Return 400/422 for missing fields.",
                        response_code=status,
                    ))

        for prop_name, prop_schema in properties.items():
            prop_type = prop_schema.get("type", "string")
            payloads = INPUT_VALIDATION_PAYLOADS.get(prop_type, INPUT_VALIDATION_PAYLOADS["string"])
            base_body = {k: prop_schema.get("example", "test") for k, v in properties.items()}

            for payload in payloads[:3]:
                test_body = {**base_body, prop_name: payload}
                status, body, resp_time = await self._request(method, url, json_data=test_body, headers=headers)
                if status == 500:
                    findings.append(Finding(
                        vuln_type="Input Validation (Body - 500 Error)",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=prop_name,
                        payload=str(payload)[:200],
                        evidence=f"HTTP 500 with body payload: {str(payload)[:100]}",
                        description=f"Server crash on body field '{prop_name}' with {prop_type} type.",
                        remediation="Validate all body inputs server-side. Use schema validation libraries.",
                        response_code=status,
                    ))
                    break

        return findings


# ---------------------------------------------------------------------------
# Mass Assignment Tester
# ---------------------------------------------------------------------------

class MassAssignmentTester:
    """Detect mass assignment vulnerabilities."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def _request(
        self, method: str, url: str, json_data: dict = None, headers: dict = None
    ) -> tuple[int, str, float]:
        async with self._semaphore:
            start = time.time()
            try:
                kwargs = {"timeout": aiohttp.ClientTimeout(total=15)}
                if headers:
                    kwargs["headers"] = headers
                if json_data is not None:
                    kwargs["json"] = json_data
                async with getattr(self.session, method.lower())(url, **kwargs) as resp:
                    body = await resp.text(errors="ignore")
                    return resp.status, body, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, "", time.time() - start

    async def test_mass_assignment(
        self, url: str, method: str, base_body: dict = None,
        headers: dict = None
    ) -> list[Finding]:
        """Test for mass assignment by injecting extra fields."""
        findings = []
        if base_body is None:
            base_body = {}

        test_fields = random_fields_sample(MASS_ASSIGNMENT_FIELDS, max_count=5)
        malicious_body = {**base_body}

        for field_name in test_fields:
            if field_name == "admin":
                malicious_body[field_name] = True
            elif field_name in ("balance", "credit", "credits", "points", "price", "amount", "discount", "cost"):
                malicious_body[field_name] = 999999
            elif field_name in ("id", "user_id", "userId", "account_id"):
                malicious_body[field_name] = 1
            else:
                malicious_body[field_name] = "admin"

        status, body, _ = await self._request(method, url, json_data=malicious_body, headers=headers)

        if status in (200, 201):
            try:
                resp_data = json.loads(body)
                if isinstance(resp_data, dict):
                    for field_name in test_fields:
                        if field_name in resp_data and resp_data[field_name] == malicious_body[field_name]:
                            findings.append(Finding(
                                vuln_type="Mass Assignment",
                                severity=Severity.CRITICAL,
                                url=url,
                                endpoint=url,
                                method=method,
                                parameter=field_name,
                                payload=str(malicious_body[field_name]),
                                evidence=f"Field '{field_name}' accepted and reflected in response",
                                description=f"Mass assignment vulnerability: '{field_name}' was set to '{malicious_body[field_name]}'",
                                remediation="Use allowlists for mass assignment. Explicitly define which fields can be set by clients.",
                                response_code=status,
                                details={"fields_tested": test_fields},
                            ))
            except json.JSONDecodeError:
                pass

        return findings

    async def test_create_vs_update(
        self, url: str, method: str, headers: dict = None
    ) -> list[Finding]:
        """Test if read-only fields can be set via creation/update."""
        findings = []
        read_only_fields = ["id", "created_at", "updated_at", "created_by", "updated_by"]

        base_body = {"name": "test", "email": "test@example.com"}
        payload = {**base_body}
        for field in read_only_fields:
            payload[field] = "injected_value"

        status, body, _ = await self._request(method, url, json_data=payload, headers=headers)

        if status in (200, 201):
            try:
                resp_data = json.loads(body)
                if isinstance(resp_data, dict):
                    for field in read_only_fields:
                        if field in resp_data and resp_data[field] == "injected_value":
                            findings.append(Finding(
                                vuln_type="Mass Assignment (Read-Only Fields)",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=field,
                                evidence=f"Read-only field '{field}' was accepted",
                                description=f"Read-only field '{field}' can be set via API request.",
                                remediation="Reject read-only fields in input. Use DTOs or serializers with explicit field allowlists.",
                                response_code=status,
                            ))
            except json.JSONDecodeError:
                pass

        return findings


def random_fields_sample(fields: list, max_count: int = 5) -> list:
    """Take a deterministic sample of fields for testing."""
    return fields[:max_count]


# ---------------------------------------------------------------------------
# IDOR Tester
# ---------------------------------------------------------------------------

class IDORTester:
    """Detect Insecure Direct Object Reference vulnerabilities."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def _request(
        self, url: str, headers: dict = None, params: dict = None
    ) -> tuple[int, str, dict, float]:
        async with self._semaphore:
            start = time.time()
            try:
                kwargs = {"timeout": aiohttp.ClientTimeout(total=15)}
                if headers:
                    kwargs["headers"] = headers
                if params:
                    kwargs["params"] = params
                async with self.session.get(url, **kwargs) as resp:
                    body = await resp.text(errors="ignore")
                    resp_headers = dict(resp.headers)
                    return resp.status, body, resp_headers, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, "", {}, time.time() - start

    async def test_idor_endpoints(
        self, endpoints: list[APIEndpoint], base_url: str, headers: dict = None
    ) -> list[Finding]:
        """Test endpoints with ID parameters for IDOR."""
        findings = []
        id_param_pattern = re.compile(r"\{(\w*id\w*)\}", re.IGNORECASE)

        for ep in endpoints:
            matches = id_param_pattern.findall(ep.path)
            if not matches:
                matches = [
                    p["name"] for p in ep.parameters
                    if "id" in p.get("name", "").lower()
                ]

            if not matches:
                continue

            for param_name in matches:
                url = f"{base_url.rstrip('/')}{ep.path}"
                results = []

                for test_id in IDOR_ID_PAYLOADS:
                    test_url = re.sub(r"\{[^}]+\}", test_id, url)
                    status, body, resp_headers, resp_time = await self._request(test_url, headers=headers)
                    results.append({
                        "id": test_id,
                        "status": status,
                        "length": len(body),
                        "body": body[:500],
                    })
                    await asyncio.sleep(0.1)

                unique_statuses = set(r["status"] for r in results)
                unique_lengths = set(r["length"] for r in results if r["status"] == 200)

                if len(unique_statuses) > 1 and 200 in unique_statuses:
                    accessible_ids = [r for r in results if r["status"] == 200]
                    if len(accessible_ids) > 1:
                        findings.append(Finding(
                            vuln_type="IDOR - Multiple IDs Accessible",
                            severity=Severity.HIGH,
                            url=url,
                            endpoint=ep.path,
                            method=ep.method,
                            parameter=param_name,
                            evidence=f"Accessible IDs: {[r['id'] for r in accessible_ids]}",
                            description=f"Multiple resource IDs accessible without authorization check.",
                            remediation="Implement object-level authorization. Verify user has access to each resource.",
                            response_code=200,
                            details={
                                "accessible_ids": [r["id"] for r in accessible_ids],
                                "total_tested": len(IDOR_ID_PAYLOADS),
                            },
                        ))

                for r in results:
                    if r["status"] in (200, 201) and len(r["body"]) > 100:
                        try:
                            data = json.loads(r["body"])
                            if isinstance(data, dict) and len(data) > 3:
                                findings.append(Finding(
                                    vuln_type="IDOR - Object Data Exposure",
                                    severity=Severity.HIGH,
                                    url=re.sub(r"\{[^}]+\}", r["id"], url),
                                    endpoint=ep.path,
                                    method=ep.method,
                                    parameter=param_name,
                                    payload=r["id"],
                                    evidence=f"Full object data returned for ID {r['id']}",
                                    description=f"Full object data exposed for ID {r['id']}. May indicate missing authorization.",
                                    remediation="Implement authorization checks. Return only fields the user is authorized to see.",
                                    response_code=r["status"],
                                    details={"response_keys": list(data.keys())[:10]},
                                ))
                                break
                        except json.JSONDecodeError:
                            pass

        return findings

    async def test_parameter_tampering(
        self, url: str, method: str = "GET",
        params: dict = None, headers: dict = None
    ) -> list[Finding]:
        """Test for IDOR via query parameter tampering."""
        findings = []
        if not params:
            return findings

        id_params = [k for k in params if "id" in k.lower()]
        for param in id_params:
            original_val = params[param]
            for tampered_val in IDOR_ID_PAYLOADS:
                if tampered_val == original_val:
                    continue
                tampered_params = {**params, param: tampered_val}
                status, body, _, resp_time = await self._request(url, headers=headers, params=tampered_params)
                if status in (200, 201):
                    findings.append(Finding(
                        vuln_type="IDOR - Parameter Tampering",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload=f"{param}={tampered_val}",
                        evidence=f"HTTP {status} with tampered {param}",
                        description=f"Access granted with different {param} value.",
                        remediation="Validate object ownership server-side. Do not rely on client-provided IDs alone.",
                        response_code=status,
                    ))
                    break

        return findings


# ---------------------------------------------------------------------------
# Security Header Tester
# ---------------------------------------------------------------------------

class SecurityHeaderTester:
    """Check API security headers."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def check_headers(self, url: str) -> list[Finding]:
        findings = []
        async with self._semaphore:
            try:
                async with self.session.get(
                    url, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    headers = dict(resp.headers)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return findings

        for header_name, config in SECURITY_HEADERS.items():
            if header_name not in headers:
                findings.append(Finding(
                    vuln_type="Missing Security Header",
                    severity=config["severity"],
                    url=url,
                    header=header_name,
                    description=config["description"],
                    remediation=f"Add {header_name} header to API responses.",
                ))

        if "X-RateLimit-Limit" in headers or "Retry-After" in headers:
            findings.append(Finding(
                vuln_type="Rate Limit Headers Present",
                severity=Severity.INFO,
                url=url,
                evidence="Rate limit headers detected",
                description="API exposes rate limit information in headers.",
            ))

        return findings


# ---------------------------------------------------------------------------
# GraphQL Tester
# ---------------------------------------------------------------------------

class GraphQLTester:
    """Test GraphQL APIs for common vulnerabilities."""

    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            types {
                name
                kind
                fields {
                    name
                    args { name type { name kind ofType { name } } }
                    type { name kind ofType { name } }
                }
            }
        }
    }
    """

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def _graphql_request(
        self, url: str, query: str, headers: dict = None
    ) -> tuple[int, str, float]:
        async with self._semaphore:
            start = time.time()
            try:
                kwargs = {"timeout": aiohttp.ClientTimeout(total=15)}
                if headers:
                    kwargs["headers"] = headers
                async with self.session.post(
                    url, json={"query": query}, **kwargs
                ) as resp:
                    body = await resp.text(errors="ignore")
                    return resp.status, body, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, "", time.time() - start

    async def test_introspection(self, url: str, headers: dict = None) -> list[Finding]:
        findings = []
        status, body, _ = await self._graphql_request(url, self.INTROSPECTION_QUERY, headers)

        if status == 200:
            try:
                data = json.loads(body)
                if "data" in data and data["data"] and "__schema" in data.get("data", {}):
                    schema = data["data"]["__schema"]
                    types = [t for t in schema.get("types", []) if not t["name"].startswith("__")]
                    findings.append(Finding(
                        vuln_type="GraphQL Introspection Enabled",
                        severity=Severity.MEDIUM,
                        url=url,
                        evidence=f"Introspection query successful. {len(types)} types exposed.",
                        description="GraphQL introspection is enabled, exposing full API schema.",
                        remediation="Disable introspection in production. Use persisted queries.",
                        details={"types_count": len(types)},
                    ))
            except json.JSONDecodeError:
                pass

        return findings

    async def test_depth_limiting(self, url: str, headers: dict = None) -> list[Finding]:
        findings = []
        deep_query = "query { " + "a: __typename " * 50 + "}"
        status, body, resp_time = await self._graphql_request(url, deep_query, headers)

        if status == 200:
            try:
                data = json.loads(body)
                if "data" in data:
                    findings.append(Finding(
                        vuln_type="GraphQL No Depth Limiting",
                        severity=Severity.MEDIUM,
                        url=url,
                        evidence="Deeply nested query accepted without error",
                        description="GraphQL accepts arbitrarily deep queries, enabling DoS attacks.",
                        remediation="Implement query depth limiting and complexity analysis.",
                        response_code=status,
                        response_time=resp_time,
                    ))
            except json.JSONDecodeError:
                pass

        return findings

    async def test_batch_queries(self, url: str, headers: dict = None) -> list[Finding]:
        findings = []
        batch = [{"query": "{ __typename }"} for _ in range(20)]
        status, body, _ = await self._graphql_request_raw(url, batch, headers)

        if status == 200:
            findings.append(Finding(
                vuln_type="GraphQL Batch Queries Allowed",
                severity=Severity.LOW,
                url=url,
                evidence="Batch query with 20 operations accepted",
                description="GraphQL accepts batch queries. May be abused for DoS or bypassing rate limits.",
                remediation="Limit batch size or disable batching in production.",
            ))

        return findings

    async def _graphql_request_raw(
        self, url: str, payload, headers: dict = None
    ) -> tuple[int, str, float]:
        async with self._semaphore:
            start = time.time()
            try:
                kwargs = {"timeout": aiohttp.ClientTimeout(total=15)}
                if headers:
                    kwargs["headers"] = headers
                async with self.session.post(url, json=payload, **kwargs) as resp:
                    body = await resp.text(errors="ignore")
                    return resp.status, body, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, "", time.time() - start


# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------

class APISecurityTester:
    """Orchestrate all API security testing modules."""

    def __init__(
        self,
        target: str,
        output: str = None,
        rate_limit: float = 5.0,
        timeout: int = 15,
        spec_url: str = None,
        token: str = None,
        api_type: str = "auto",
        test_idor: bool = True,
        test_auth: bool = True,
        test_rate_limit: bool = True,
        test_input: bool = True,
        test_mass_assignment: bool = True,
        test_graphql: bool = True,
    ):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.output = output or f"api_test_{urllib.parse.urlparse(self.target).netloc.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.spec_url = spec_url
        self.token = token
        self.api_type = api_type
        self.test_flags = {
            "idor": test_idor,
            "auth": test_auth,
            "rate_limit": test_rate_limit,
            "input": test_input,
            "mass_assignment": test_mass_assignment,
            "graphql": test_graphql,
        }
        self.results = TestResults(
            target=self.target,
            timestamp=datetime.utcnow().isoformat() + "Z",
        )
        self._session: Optional[aiohttp.ClientSession] = None
        self._endpoints: list[APIEndpoint] = []

    async def _create_session(self) -> aiohttp.ClientSession:
        headers = {
            "User-Agent": "APITester/1.0 (Security Testing)",
            "Accept": "application/json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        connector = aiohttp.TCPConnector(limit=self.rate_limit, ssl=False)
        return aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers=headers,
        )

    async def _detect_api_type(self) -> str:
        """Auto-detect if target is REST or GraphQL."""
        if self.api_type != "auto":
            return self.api_type

        graphql_paths = ["/graphql", "/graphiql", "/v1/graphql", "/api/graphql"]
        parsed = urllib.parse.urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in graphql_paths:
            url = f"{base}{path}"
            try:
                async with self.session.post(
                    url, json={"query": "{ __typename }"},
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="ignore")
                        if '{"data"' in body:
                            logger.info(f"GraphQL endpoint detected at {url}")
                            self.target = url
                            return "graphql"
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

        return "rest"

    async def run(self) -> dict:
        """Execute full API security testing."""
        logger.info(f"Starting API security test for {self.target}")
        start_time = time.time()

        self._session = await self._create_session()

        try:
            self.api_type = await self._detect_api_type()
            self.results.api_type = self.api_type
            logger.info(f"API type: {self.api_type}")

            if self.api_type == "graphql":
                await self._run_graphql_tests()
            else:
                await self._run_rest_tests()

        finally:
            if self._session:
                await self._session.close()

        self.results.duration_seconds = round(time.time() - start_time, 1)

        logger.info("=" * 60)
        logger.info("API Security Test Complete")
        logger.info("=" * 60)
        summary = self.results.to_dict()["summary"]
        logger.info(f"Endpoints tested: {self.results.endpoints_found}")
        logger.info(f"Total findings: {summary['total_findings']}")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if summary.get(sev, 0) > 0:
                logger.info(f"  {sev.upper()}: {summary[sev]}")
        logger.info(f"Duration: {self.results.duration_seconds}s")

        return self.results.to_dict()

    async def _run_rest_tests(self):
        """Run tests against REST API."""
        parsed = urllib.parse.urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Phase 1: Discover API spec
        logger.info("=" * 60)
        logger.info("Phase 1: API Spec Discovery")
        logger.info("=" * 60)
        parser = OpenAPIParser(self._session)
        spec = None

        if self.spec_url:
            try:
                async with self.session.get(self.spec_url) as resp:
                    if resp.status == 200:
                        spec = json.loads(await resp.text())
            except Exception:
                pass

        if not spec:
            spec = await parser.discover_spec(base_url)

        if spec:
            self._endpoints = parser.parse_endpoints(spec)
            self.results.endpoints_found = len(self._endpoints)
        else:
            logger.warning("No API spec found. Using target URL as single endpoint.")
            self._endpoints = [
                APIEndpoint(path=parsed.path or "/", method="get"),
                APIEndpoint(path=parsed.path or "/", method="post"),
            ]
            self.results.endpoints_found = len(self._endpoints)

        # Phase 2: Security headers
        logger.info("=" * 60)
        logger.info("Phase 2: Security Headers")
        logger.info("=" * 60)
        header_tester = SecurityHeaderTester(self._session, self.rate_limit)
        header_findings = await header_tester.check_headers(self.target)
        self.results.findings.extend(header_findings)
        self.results.tests_run["security_headers"] = len(header_findings)

        # Phase 3: Auth testing
        if self.test_flags["auth"] and self._endpoints:
            logger.info("=" * 60)
            logger.info("Phase 3: Authentication Testing")
            logger.info("=" * 60)
            auth_tester = AuthTester(self._session, self.rate_limit)
            auth_progress = ProgressBar(len(self._endpoints), "Auth testing")

            for ep in self._endpoints:
                url = f"{base_url}{ep.path}"
                findings = await auth_tester.test_broken_auth(url, ep.method)
                self.results.findings.extend(findings)

                findings = await auth_tester.test_token_leakage(url, ep.method)
                self.results.findings.extend(findings)
                auth_progress.update()
            auth_progress.finish()
            self.results.tests_run["auth"] = len(self.results.findings)

        # Phase 4: Rate limiting
        if self.test_flags["rate_limit"] and self._endpoints:
            logger.info("=" * 60)
            logger.info("Phase 4: Rate Limiting Detection")
            logger.info("=" * 60)
            rl_tester = RateLimitTester(self._session, self.rate_limit)
            rl_progress = ProgressBar(len(self._endpoints[:5]), "Rate limit testing")

            for ep in self._endpoints[:5]:
                url = f"{base_url}{ep.path}"
                findings = await rl_tester.detect_rate_limiting(url, ep.method)
                self.results.findings.extend(findings)

                findings = await rl_tester.test_rate_limit_bypass(url, ep.method)
                self.results.findings.extend(findings)
                rl_progress.update()
            rl_progress.finish()

        # Phase 5: Input validation
        if self.test_flags["input"] and self._endpoints:
            logger.info("=" * 60)
            logger.info("Phase 5: Input Validation Testing")
            logger.info("=" * 60)
            input_tester = InputValidationTester(self._session, self.rate_limit)
            input_progress = ProgressBar(len(self._endpoints), "Input validation")

            for ep in self._endpoints:
                url = f"{base_url}{ep.path}"
                findings = await input_tester.test_endpoint_inputs(
                    url, ep.method, ep.parameters, ep.request_body
                )
                self.results.findings.extend(findings)
                input_progress.update()
            input_progress.finish()
            self.results.tests_run["input_validation"] = len(self.results.findings)

        # Phase 6: Mass assignment
        if self.test_flags["mass_assignment"] and self._endpoints:
            logger.info("=" * 60)
            logger.info("Phase 6: Mass Assignment Testing")
            logger.info("=" * 60)
            ma_tester = MassAssignmentTester(self._session, self.rate_limit)
            ma_progress = ProgressBar(len(self._endpoints), "Mass assignment")

            for ep in self._endpoints:
                if ep.method in ("post", "put", "patch"):
                    url = f"{base_url}{ep.path}"
                    base_body = self._get_sample_body(ep)
                    findings = await ma_tester.test_mass_assignment(url, ep.method, base_body)
                    self.results.findings.extend(findings)

                    findings = await ma_tester.test_create_vs_update(url, ep.method)
                    self.results.findings.extend(findings)
                ma_progress.update()
            ma_progress.finish()
            self.results.tests_run["mass_assignment"] = len(self.results.findings)

        # Phase 7: IDOR testing
        if self.test_flags["idor"] and self._endpoints:
            logger.info("=" * 60)
            logger.info("Phase 7: IDOR Testing")
            logger.info("=" * 60)
            idor_tester = IDORTester(self._session, self.rate_limit)
            idor_findings = await idor_tester.test_idor_endpoints(
                self._endpoints, base_url
            )
            self.results.findings.extend(idor_findings)
            self.results.tests_run["idor"] = len(idor_findings)

    async def _run_graphql_tests(self):
        """Run tests against GraphQL API."""
        logger.info("=" * 60)
        logger.info("GraphQL Security Testing")
        logger.info("=" * 60)

        gql_tester = GraphQLTester(self._session, self.rate_limit)

        findings = await gql_tester.test_introspection(self.target)
        self.results.findings.extend(findings)

        findings = await gql_tester.test_depth_limiting(self.target)
        self.results.findings.extend(findings)

        findings = await gql_tester.test_batch_queries(self.target)
        self.results.findings.extend(findings)

        self.results.endpoints_found = len(self.results.findings)

    def _get_sample_body(self, endpoint: APIEndpoint) -> dict:
        """Generate a sample request body from endpoint spec."""
        if endpoint.request_body:
            schema = endpoint.request_body.get("schema", {})
            properties = schema.get("properties", {})
            if properties:
                return {
                    k: v.get("example", v.get("default", "test"))
                    for k, v in properties.items()
                }
        return {"name": "test", "email": "test@test.com"}

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
        description="API Security Tester - REST & GraphQL API security analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://api.example.com
  %(prog)s https://api.example.com --spec https://api.example.com/openapi.json
  %(prog)s https://api.example.com --token eyJhbGciOiJIUzI1NiJ9...
  %(prog)s https://api.example.com --type graphql --url https://api.example.com/graphql
  %(prog)s https://api.example.com --no-idor --no-auth -o results.json
        """,
    )
    parser.add_argument("target", help="Target API base URL")
    parser.add_argument("-o", "--output", help="Output JSON file path")
    parser.add_argument("--spec", dest="spec_url", help="OpenAPI/Swagger spec URL")
    parser.add_argument("--token", help="Authentication token (Bearer)")
    parser.add_argument(
        "--type", dest="api_type", default="auto",
        choices=["auto", "rest", "graphql"],
        help="API type (default: auto-detect)",
    )
    parser.add_argument("--rate", type=float, default=5.0, help="Max concurrent requests (default: 5)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--no-idor", action="store_true", help="Skip IDOR testing")
    parser.add_argument("--no-auth", action="store_true", help="Skip authentication testing")
    parser.add_argument("--no-rate-limit", action="store_true", help="Skip rate limit testing")
    parser.add_argument("--no-input", action="store_true", help="Skip input validation testing")
    parser.add_argument("--no-mass-assignment", action="store_true", help="Skip mass assignment testing")
    parser.add_argument("--no-graphql", action="store_true", help="Skip GraphQL-specific tests")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug logging")
    parser.add_argument("--json-stdout", action="store_true", help="Print JSON results to stdout")
    return parser.parse_args()


async def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tester = APISecurityTester(
        target=args.target,
        output=args.output,
        rate_limit=args.rate,
        timeout=args.timeout,
        spec_url=args.spec_url,
        token=args.token,
        api_type=args.api_type,
        test_idor=not args.no_idor,
        test_auth=not args.no_auth,
        test_rate_limit=not args.no_rate_limit,
        test_input=not args.no_input,
        test_mass_assignment=not args.no_mass_assignment,
        test_graphql=not args.no_graphql,
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
        logger.error(f"API test failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
