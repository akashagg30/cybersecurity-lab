#!/usr/bin/env python3
"""Validate security findings to eliminate false positives"""
import aiohttp
import asyncio
import json
from typing import Dict, List, Optional

class FindingValidator:
    """Validate security findings before reporting"""
    
    def __init__(self):
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def validate_directory(self, url: str, path: str) -> Dict:
        """Validate if a directory/file actually exists"""
        full_url = f"{url.rstrip('/')}/{path}"
        
        try:
            async with self.session.get(full_url, timeout=10, allow_redirects=True) as resp:
                final_url = str(resp.url)
                status = resp.status
                body = await resp.text()
                
                # Check if redirected to different domain
                from urllib.parse import urlparse
                original_domain = urlparse(url).netloc
                final_domain = urlparse(final_url).netloc
                
                is_redirect = original_domain != final_domain
                is_404 = status == 404
                is_error_page = "not found" in body.lower() or "404" in body
                
                return {
                    "path": path,
                    "original_url": full_url,
                    "final_url": final_url,
                    "status": status,
                    "is_redirect": is_redirect,
                    "is_404": is_404,
                    "is_error_page": is_error_page,
                    "actually_exists": not is_404 and not is_error_page and not is_redirect,
                    "severity": "high" if not is_404 and not is_redirect else "info"
                }
        except Exception as e:
            return {
                "path": path,
                "error": str(e),
                "actually_exists": False,
                "severity": "info"
            }
    
    async def validate_sqli(self, url: str, param: str, payload: str) -> Dict:
        """Validate SQL injection finding"""
        test_url = f"{url}?{param}={payload}"
        
        try:
            async with self.session.get(test_url, timeout=10) as resp:
                body = await resp.text()
                status = resp.status
                
                # SQL error signatures
                sql_errors = [
                    "sql syntax", "mysql_fetch", "ORA-", "PostgreSQL",
                    "sqlite3", "Microsoft OLE DB", "ODBC SQL Server",
                    "Unclosed quotation mark", "unterminated string",
                    "SQL command not properly ended", "Invalid column name",
                    "Table doesn't exist", "you have an error in your sql syntax"
                ]
                
                has_sql_error = any(err.lower() in body.lower() for err in sql_errors)
                
                # Check for time-based indicators
                has_time_delay = False  # Would need timing analysis
                
                return {
                    "payload": payload,
                    "status": status,
                    "has_sql_error": has_sql_error,
                    "has_time_delay": has_time_delay,
                    "actually_vulnerable": has_sql_error or has_time_delay,
                    "evidence": body[:200] if has_sql_error else None
                }
        except Exception as e:
            return {
                "payload": payload,
                "error": str(e),
                "actually_vulnerable": False
            }
    
    async def validate_xss(self, url: str, param: str, payload: str) -> Dict:
        """Validate XSS finding"""
        test_url = f"{url}?{param}={payload}"
        
        try:
            async with self.session.get(test_url, timeout=10) as resp:
                body = await resp.text()
                
                # Check if payload is reflected
                is_reflected = payload in body
                
                # Check if reflected in dangerous context
                dangerous_contexts = [
                    "<script", "javascript:", "onerror=", "onload=",
                    "onclick=", "onmouseover=", "eval(", "document.cookie"
                ]
                
                in_dangerous_context = any(ctx in body.lower() for ctx in dangerous_contexts)
                
                return {
                    "payload": payload,
                    "is_reflected": is_reflected,
                    "in_dangerous_context": in_dangerous_context,
                    "actually_vulnerable": is_reflected and in_dangerous_context,
                    "evidence": body[:200] if is_reflected else None
                }
        except Exception as e:
            return {
                "payload": payload,
                "error": str(e),
                "actually_vulnerable": False
            }
    
    async def validate_exposed_path(self, url: str, path: str) -> Dict:
        """Validate if a path is actually exposed"""
        full_url = f"{url.rstrip('/')}/{path}"
        
        try:
            async with self.session.get(full_url, timeout=10, allow_redirects=False) as resp:
                status = resp.status
                headers = dict(resp.headers)
                location = headers.get("Location", "")
                
                # Check if it's a real redirect or just routing
                from urllib.parse import urlparse
                original_domain = urlparse(url).netloc
                
                is_same_domain_redirect = original_domain in location
                is_404 = status == 404
                
                return {
                    "path": path,
                    "status": status,
                    "location": location,
                    "is_same_domain_redirect": is_same_domain_redirect,
                    "is_404": is_404,
                    "actually_exposed": not is_404 and not is_same_domain_redirect,
                    "severity": "medium" if not is_404 and not is_same_domain_redirect else "info"
                }
        except Exception as e:
            return {
                "path": path,
                "error": str(e),
                "actually_exposed": False,
                "severity": "info"
            }

async def validate_findings(findings: List[Dict], target_url: str) -> List[Dict]:
    """Validate a list of findings"""
    validated = []
    
    async with FindingValidator() as validator:
        for finding in findings:
            vuln_type = finding.get("vuln_type", "")
            
            if "Directory" in vuln_type or "Path" in vuln_type:
                result = await validator.validate_exposed_path(target_url, finding.get("path", ""))
                finding.update(result)
            
            elif "SQL Injection" in vuln_type:
                result = await validator.validate_sqli(
                    finding.get("url", ""),
                    finding.get("parameter", ""),
                    finding.get("payload", "")
                )
                finding.update(result)
            
            elif "XSS" in vuln_type:
                result = await validator.validate_xss(
                    finding.get("url", ""),
                    finding.get("parameter", ""),
                    finding.get("payload", "")
                )
                finding.update(result)
            
            validated.append(finding)
    
    return validated

if __name__ == "__main__":
    # Test the validator
    import sys
    
    async def main():
        validator = FindingValidator()
        async with validator:
            # Test directory validation
            result = await validator.validate_exposed_path("https://oneresume.life", ".git")
            print(f".git: {json.dumps(result, indent=2)}")
    
    asyncio.run(main())
