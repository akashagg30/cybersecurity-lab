#!/usr/bin/env python3
"""
Recon Tool - Advanced Domain Reconnaissance
Subdomain enumeration, port scanning, and technology fingerprinting.
"""

import asyncio
import argparse
import json
import logging
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import aiohttp
    from dns.resolver import Resolver, NoAnswer, NoNameservers, NXDOMAIN
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
logger = logging.getLogger("recon")


class ProgressBar:
    """Simple progress indicator for async operations."""

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


class SubdomainEnumerator:
    """Enumerate subdomains using DNS resolution and subfinder."""

    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "ns3",
        "dns", "dns1", "dns2", "mx", "mx1", "mx2", "webmail",
        "cpanel", "whm", "api", "dev", "staging", "test", "admin",
        "portal", "vpn", "remote", "git", "gitlab", "github",
        "ci", "jenkins", "travis", "cdn", "static", "assets",
        "img", "images", "media", "app", "apps", "beta", "demo",
        "docs", "wiki", "help", "support", "status", "monitor",
        "grafana", "kibana", "elastic", "db", "mysql", "postgres",
        "redis", "mongo", "es", "search", "cache", "proxy",
        "lb", "haproxy", "nginx", "apache", "iis", "tomcat",
        "k8s", "kubernetes", "docker", "registry", "harbor",
        "cloud", "aws", "gcp", "azure", "s3", "storage",
        "backup", "bak", "old", "archive", "logs", "log",
        "auth", "sso", "oauth", "ldap", "ad", "dc",
        "mx1", "mx2", "mx3", "smtp1", "smtp2",
        "shop", "store", "pay", "billing", "crm", "erp",
        "hr", "intranet", "internal", "office", "lan",
    ]

    def __init__(self, domain: str):
        self.domain = domain
        self.resolver = Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 5

    async def resolve_subdomain(self, subdomain: str, progress: Optional[ProgressBar] = None) -> Optional[str]:
        """Resolve a single subdomain."""
        fqdn = f"{subdomain}.{self.domain}"
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None, lambda: self.resolver.resolve(fqdn, "A")
            )
            ips = [str(r) for r in answers]
            logger.debug(f"Found: {fqdn} -> {', '.join(ips)}")
            return fqdn
        except (NXDOMAIN, NoAnswer, NoNameservers, OSError) as e:
            logger.debug(f"Failed: {fqdn} - {e}")
            return None
        finally:
            if progress:
                progress.update()

    async def enumerate_bruteforce(self) -> list[str]:
        """Bruteforce common subdomain names."""
        logger.info(f"Starting bruteforce enumeration for {self.domain}")
        progress = ProgressBar(len(self.COMMON_SUBDOMAINS), "DNS bruteforce")
        tasks = [self.resolve_subdomain(sub, progress) for sub in self.COMMON_SUBDOMAINS]
        results = await asyncio.gather(*tasks)
        progress.finish()
        return [r for r in results if r]

    async def enumerate_subfinder(self) -> list[str]:
        """Run subfinder as subprocess for passive enumeration."""
        logger.info(f"Running subfinder for {self.domain}")
        try:
            cmd = [
                "subfinder",
                "-d", self.domain,
                "-silent",
                "-timeout", "10",
            ]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
            if process.returncode == 0:
                subdomains = stdout.decode().strip().split("\n")
                return [s.strip() for s in subdomains if s.strip()]
            else:
                logger.warning(f"subfinder returned {process.returncode}: {stderr.decode()}")
                return []
        except FileNotFoundError:
            logger.warning("subfinder not found. Install from: https://github.com/projectdiscovery/subfinder")
            return []
        except asyncio.TimeoutError:
            logger.warning("subfinder timed out")
            return []

    async def enumerate(self) -> list[str]:
        """Run all enumeration methods in parallel."""
        bruteforce_task = self.enumerate_bruteforce()
        subfinder_task = self.enumerate_subfinder()

        bruteforce_results, subfinder_results = await asyncio.gather(
            bruteforce_task, subfinder_task
        )

        all_subdomains = set(bruteforce_results + subfinder_results)
        sorted_subdomains = sorted(all_subdomains)
        logger.info(f"Found {len(sorted_subdomains)} unique subdomains")
        return sorted_subdomains


class PortScanner:
    """Port scanning using nmap or raw sockets."""

    DEFAULT_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1723, 3306, 3389,
        5900, 8080, 8443, 8888, 9090,
    ]

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    async def scan_nmap(self, host: str, ports: str = "1-1000") -> list[dict]:
        """Scan using nmap."""
        logger.info(f"Running nmap scan on {host}")
        try:
            cmd = [
                "nmap",
                "-sV",
                "-T4",
                "--open",
                "-p", ports,
                "-oX", "-",
                host,
            ]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)

            if process.returncode != 0:
                logger.warning(f"nmap returned {process.returncode}")
                return await self.scan_raw(host)

            return self._parse_nmap_xml(stdout.decode())
        except FileNotFoundError:
            logger.warning("nmap not found. Falling back to raw socket scan")
            return await self.scan_raw(host)
        except asyncio.TimeoutError:
            logger.warning("nmap scan timed out")
            return []

    def _parse_nmap_xml(self, xml_output: str) -> list[dict]:
        """Parse nmap XML output."""
        import xml.etree.ElementTree as ET
        results = []
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall(".//host"):
                ports = host.findall(".//port")
                for port_elem in ports:
                    port_id = port_elem.get("portid")
                    protocol = port_elem.get("protocol", "tcp")
                    state = port_elem.find("state")
                    service = port_elem.find("service")
                    if state is not None and state.get("state") == "open":
                        result = {
                            "port": int(port_id),
                            "protocol": protocol,
                            "state": "open",
                            "service": service.get("name", "unknown") if service is not None else "unknown",
                            "version": service.get("version", "") if service is not None else "",
                        }
                        results.append(result)
        except ET.ParseError as e:
            logger.error(f"Failed to parse nmap output: {e}")
        return results

    async def scan_raw(self, host: str, ports: list[int] = None) -> list[dict]:
        """Raw socket scan fallback."""
        if ports is None:
            ports = self.DEFAULT_PORTS
        logger.info(f"Running raw scan on {host} ({len(ports)} ports)")
        progress = ProgressBar(len(ports), "Port scan")
        results = []

        async def check_port(port: int):
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout,
                )
                writer.close()
                await writer.wait_closed()
                return {"port": port, "protocol": "tcp", "state": "open", "service": "", "version": ""}
            except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                return None
            finally:
                progress.update()

        tasks = [check_port(port) for port in ports]
        scan_results = await asyncio.gather(*tasks)
        progress.finish()
        return [r for r in scan_results if r is not None]

    async def scan(self, host: str, ports: str = "1-1000") -> list[dict]:
        """Try nmap first, fall back to raw scan."""
        return await self.scan_nmap(host, ports)


class TechFingerprinter:
    """Fingerprint technologies from HTTP responses."""

    TECHNOLOGY_SIGNATURES = {
        "headers": {
            "Server": {
                "nginx": "Nginx",
                "Apache": "Apache",
                "Microsoft-IIS": "Microsoft IIS",
                "Cloudflare": "Cloudflare",
                "GSE": "Google Web Server",
                "AmazonS3": "Amazon S3",
                "Varnish": "Varnish",
                "LiteSpeed": "LiteSpeed",
                "Caddy": "Caddy",
            },
            "X-Powered-By": {
                "PHP": "PHP",
                "ASP.NET": "ASP.NET",
                "Express": "Express.js",
                "Django": "Django",
                "Ruby on Rails": "Ruby on Rails",
                "Spring": "Spring",
            },
            "X-AspNet-Version": {"": "ASP.NET"},
            "X-Generator": {
                "WordPress": "WordPress",
                "Drupal": "Drupal",
            },
        },
        "meta_tags": {
            "generator": {
                "WordPress": "WordPress",
                "Joomla": "Joomla",
                "Drupal": "Drupal",
                "Hugo": "Hugo",
                "Jekyll": "Jekyll",
                "Next.js": "Next.js",
                "Nuxt.js": "Nuxt.js",
                "Gatsby": "Gatsby",
            },
        },
        "body_patterns": {
            "wp-content": "WordPress",
            "wp-includes": "WordPress",
            "/sites/default/files": "Drupal",
            "Joomla!": "Joomla",
            "shopify": "Shopify",
            "Wix.com": "Wix",
            "Squarespace": "Squarespace",
            "Webflow": "Webflow",
            "react": "React",
            "vue": "Vue.js",
            "angular": "Angular",
            "jquery": "jQuery",
            "bootstrap": "Bootstrap",
            "laravel": "Laravel",
            "django": "Django",
            "flask": "Flask",
            "fastapi": "FastAPI",
            "next": "Next.js",
            "nuxt": "Nuxt.js",
            "gatsby": "Gatsby",
        },
        "cookie_patterns": {
            "PHPSESSID": "PHP",
            "JSESSIONID": "Java",
            "connect.sid": "Express.js",
            "csrftoken": "Django",
            "laravel_session": "Laravel",
            "ASP.NET_SessionId": "ASP.NET",
            "wordpress_logged_in": "WordPress",
            "woocommerce": "WooCommerce",
            "_rails_session": "Ruby on Rails",
        },
    }

    def __init__(self):
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            headers={"User-Agent": "ReconTool/1.0"},
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    def _detect_from_headers(self, headers: dict) -> set[str]:
        techs = set()
        for header_name, sigs in self.TECHNOLOGY_SIGNATURES["headers"].items():
            header_val = headers.get(header_name, "")
            if header_val:
                for pattern, name in sigs.items():
                    if pattern.lower() in header_val.lower():
                        techs.add(name)
        return techs

    def _detect_from_meta(self, html: str) -> set[str]:
        techs = set()
        import re
        meta_pattern = re.compile(
            r'<meta\s+[^>]*name\s*=\s*["\']generator["\'][^>]*content\s*=\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        matches = meta_pattern.findall(html)
        for content in matches:
            for pattern, name in self.TECHNOLOGY_SIGNATURES["meta_tags"]["generator"].items():
                if pattern.lower() in content.lower():
                    techs.add(name)
        return techs

    def _detect_from_body(self, html: str) -> set[str]:
        techs = set()
        html_lower = html.lower()
        for pattern, name in self.TECHNOLOGY_SIGNATURES["body_patterns"].items():
            if pattern.lower() in html_lower:
                techs.add(name)
        return techs

    def _detect_from_cookies(self, cookies: list) -> set[str]:
        techs = set()
        for cookie in cookies:
            cookie_name = cookie.get("name", "")
            for pattern, name in self.TECHNOLOGY_SIGNATURES["cookie_patterns"].items():
                if pattern.lower() == cookie_name.lower():
                    techs.add(name)
        return techs

    async def fingerprint(self, url: str) -> dict:
        """Fingerprint a single URL."""
        result = {
            "url": url,
            "technologies": [],
            "headers": {},
            "status": None,
            "redirect": None,
            "error": None,
        }

        try:
            async with self.session.get(url, allow_redirects=True) as resp:
                result["status"] = resp.status
                result["headers"] = dict(resp.headers)
                result["redirect"] = str(resp.url) if str(resp.url) != url else None

                all_techs = set()
                all_techs.update(self._detect_from_headers(dict(resp.headers)))

                if resp.status == 200:
                    html = await resp.text(errors="ignore")
                    all_techs.update(self._detect_from_meta(html))
                    all_techs.update(self._detect_from_body(html))

                cookies = [
                    {"name": c.key, "value": c.value}
                    for c in resp.cookies.values()
                ]
                all_techs.update(self._detect_from_cookies(cookies))

                result["technologies"] = sorted(all_techs)

        except aiohttp.ClientError as e:
            result["error"] = str(e)
            logger.debug(f"Fingerprint error for {url}: {e}")
        except Exception as e:
            result["error"] = str(e)

        return result

    async def fingerprint_all(self, urls: list[str]) -> list[dict]:
        """Fingerprint multiple URLs in parallel."""
        logger.info(f"Fingerprinting {len(urls)} URLs")
        progress = ProgressBar(len(urls), "Fingerprinting")
        results = []

        sem = asyncio.Semaphore(10)

        async def limited_fingerprint(url: str):
            async with sem:
                result = await self.fingerprint(url)
                progress.update()
                return result

        tasks = [limited_fingerprint(url) for url in urls]
        results = await asyncio.gather(*tasks)
        progress.finish()
        return results


class ReconTool:
    """Main reconnaissance orchestrator."""

    def __init__(self, domain: str, output: str = None, ports: str = "1-1000"):
        self.domain = domain
        self.output = output or f"recon_{domain.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.ports = ports
        self.results = {
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "subdomains": [],
            "ports": {},
            "fingerprinting": [],
            "summary": {},
        }

    async def run(self) -> dict:
        """Execute full reconnaissance."""
        logger.info(f"Starting reconnaissance for {self.domain}")
        start_time = time.time()

        # Phase 1: Subdomain enumeration
        logger.info("=" * 50)
        logger.info("Phase 1: Subdomain Enumeration")
        logger.info("=" * 50)
        enumerator = SubdomainEnumerator(self.domain)
        subdomains = await enumerator.enumerate()
        self.results["subdomains"] = subdomains

        # Phase 2: Port scanning on discovered subdomains + base domain
        logger.info("=" * 50)
        logger.info("Phase 2: Port Scanning")
        logger.info("=" * 50)
        scanner = PortScanner()
        targets = list(set([self.domain] + subdomains[:20]))  # Limit to 20 for performance
        port_results = {}

        for target in targets:
            ports = await scanner.scan(target, self.ports)
            if ports:
                port_results[target] = ports

        self.results["ports"] = port_results

        # Phase 3: Technology fingerprinting
        logger.info("=" * 50)
        logger.info("Phase 3: Technology Fingerprinting")
        logger.info("=" * 50)
        urls = []
        for target in targets:
            for scheme in ["https", "http"]:
                urls.append(f"{scheme}://{target}")

        async with TechFingerprinter() as f:
            fp_results = await f.fingerprint_all(urls)

        self.results["fingerprinting"] = fp_results

        # Summary
        total_open_ports = sum(len(ports) for ports in port_results.values())
        all_techs = set()
        for fp in fp_results:
            all_techs.update(fp.get("technologies", []))

        self.results["summary"] = {
            "subdomains_found": len(subdomains),
            "hosts_with_open_ports": len(port_results),
            "total_open_ports": total_open_ports,
            "technologies_detected": sorted(all_techs),
            "duration_seconds": round(time.time() - start_time, 1),
        }

        logger.info("=" * 50)
        logger.info("Reconnaissance Complete")
        logger.info("=" * 50)
        logger.info(f"Subdomains: {len(subdomains)}")
        logger.info(f"Hosts with open ports: {len(port_results)}")
        logger.info(f"Total open ports: {total_open_ports}")
        logger.info(f"Technologies: {', '.join(sorted(all_techs)) or 'None detected'}")
        logger.info(f"Duration: {self.results['summary']['duration_seconds']}s")

        return self.results

    def save(self):
        """Save results to JSON file."""
        output_path = Path(self.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(self.results, f, indent=2)
        logger.info(f"Results saved to {output_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Advanced Domain Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com -p 80,443,8080
  %(prog)s example.com -o results.json -v
  %(prog)s example.com -p 1-65535 --no-fingerprint
        """,
    )
    parser.add_argument(
        "domain",
        help="Target domain to recon (e.g., example.com)",
    )
    parser.add_argument(
        "-p", "--ports",
        default="1-1000",
        help="Port range to scan (default: 1-1000)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output JSON file path (default: recon_<domain>_<timestamp>.json)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    parser.add_argument(
        "--no-subfinder",
        action="store_true",
        help="Skip subfinder passive enumeration",
    )
    parser.add_argument(
        "--no-fingerprint",
        action="store_true",
        help="Skip technology fingerprinting",
    )
    parser.add_argument(
        "--json-stdout",
        action="store_true",
        help="Print JSON results to stdout",
    )
    return parser.parse_args()


async def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tool = ReconTool(
        domain=args.domain,
        output=args.output,
        ports=args.ports,
    )

    try:
        results = await tool.run()
        tool.save()

        if args.json_stdout:
            print(json.dumps(results, indent=2))

    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Recon failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
