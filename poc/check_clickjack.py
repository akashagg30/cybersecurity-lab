#!/usr/bin/env python3
"""Check if site is vulnerable to clickjacking"""
import aiohttp
import asyncio

async def check_clickjacking():
    target = "https://oneresume.life"
    
    print(f"[*] Testing clickjacking on {target}")
    
    async with aiohttp.ClientSession() as session:
        async with session.get(target) as resp:
            headers = resp.headers
            
            print(f"\n[*] Response Headers:")
            print(f"  X-Frame-Options: {headers.get('X-Frame-Options', 'NOT SET')}")
            print(f"  Content-Security-Policy: {headers.get('Content-Security-Policy', 'NOT SET')}")
            
            print(f"\n[*] Analysis:")
            xfo = headers.get('X-Frame-Options', '').upper()
            csp = headers.get('Content-Security-Policy', '')
            
            if 'DENY' in xfo:
                print("  [+] X-Frame-Options: DENY - Site blocks iframe embedding")
            elif 'SAMEORIGIN' in xfo:
                print("  [!] X-Frame-Options: SAMEORIGIN - Site allows same-origin iframes")
            elif not xfo:
                print("  [-] X-Frame-Options: NOT SET - Site is VULNERABLE to clickjacking")
            else:
                print(f"  [?] X-Frame-Options: {xfo}")
            
            if 'frame-ancestors' in csp:
                print("  [+] CSP frame-ancestors set - Additional protection")
            elif csp:
                print("  [?] CSP present but no frame-ancestors directive")
            else:
                print("  [-] No CSP frame-ancestors - Additional vulnerability")
            
            print(f"\n[*] Conclusion:")
            if not xfo and 'frame-ancestors' not in csp:
                print("  [!!!] SITE IS VULNERABLE TO CLICKJACKING")
                print("  [!!!] An attacker can embed this site in a hidden iframe")
                print("  [!!!] Users can be tricked into clicking hidden elements")
            else:
                print("  [+] Site has some protection against clickjacking")

if __name__ == "__main__":
    asyncio.run(check_clickjacking())
