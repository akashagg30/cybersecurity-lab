#!/usr/bin/env python3
"""Find small startups for bug bounty"""
import aiohttp
import asyncio
import json
from typing import List, Dict

# Small startup categories to search
CATEGORIES = [
    "SaaS", "Developer Tools", "API", "Web App",
    "Analytics", "CRM", "E-commerce", "Fintech"
]

# Known small startups (manually curated)
SMALL_STARTUPS = [
    # Indian startups
    {"name": "CleverTap", "url": "https://clevertap.com", "type": "SaaS", "country": "India"},
    {"name": "WebEngage", "url": "https://webengage.com", "type": "Marketing", "country": "India"},
    {"name": "MoEngage", "url": "https://moengage.com", "type": "Marketing", "country": "India"},
    {"name": "Shiprocket", "url": "https://shiprocket.com", "type": "E-commerce", "country": "India"},
    {"name": "Razorpay", "url": "https://razorpay.com", "type": "Fintech", "country": "India"},
    {"name": "Cashfree", "url": "https://cashfree.com", "type": "Fintech", "country": "India"},
    {"name": "Groww", "url": "https://groww.in", "type": "Fintech", "country": "India"},
    {"name": "Zerodha", "url": "https://zerodha.com", "type": "Fintech", "country": "India"},
    {"name": "Unacademy", "url": "https://unacademy.com", "type": "EdTech", "country": "India"},
    {"name": "Meesho", "url": "https://meesho.com", "type": "E-commerce", "country": "India"},
    
    # Global small startups
    {"name": "Cal.com", "url": "https://cal.com", "type": "Scheduling", "country": "Global"},
    {"name": "PostHog", "url": "https://posthog.com", "type": "Analytics", "country": "Global"},
    {"name": "Linear", "url": "https://linear.app", "type": "Project Mgmt", "country": "Global"},
    {"name": "Railway", "url": "https://railway.app", "type": "Cloud", "country": "Global"},
    {"name": "Render", "url": "https://render.com", "type": "Cloud", "country": "Global"},
    {"name": "Supabase", "url": "https://supabase.com", "type": "Database", "country": "Global"},
    {"name": "Clerk", "url": "https://clerk.com", "type": "Auth", "country": "Global"},
    {"name": "Stytch", "url": "https://stytch.com", "type": "Auth", "country": "Global"},
    {"name": "WorkOS", "url": "https://workos.com", "type": "Auth", "country": "Global"},
    {"name": "Resend", "url": "https://resend.com", "type": "Email", "country": "Global"},
]

async def check_startup(session: aiohttp.ClientSession, startup: Dict) -> Dict:
    """Check if startup is active and has a web app"""
    try:
        async with session.get(startup["url"], timeout=10) as resp:
            startup["status"] = "active" if resp.status == 200 else "inactive"
            startup["response_code"] = resp.status
            
            # Check if it's a real app (not just landing page)
            body = await resp.text()
            has_login = any(word in body.lower() for word in ["login", "sign in", "register", "account"])
            has_dashboard = any(word in body.lower() for word in ["dashboard", "app", "console"])
            
            startup["has_login"] = has_login
            startup["has_dashboard"] = has_dashboard
            startup["likely_target"] = has_login or has_dashboard
            
    except Exception as e:
        startup["status"] = "error"
        startup["error"] = str(e)
        startup["likely_target"] = False
    
    return startup

async def find_startups():
    """Find small startups for bug bounty"""
    print("=" * 60)
    print("  SMALL STARTUP BUG BOUNTY TARGETS")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        tasks = [check_startup(session, s) for s in SMALL_STARTUPS]
        startups = await asyncio.gather(*tasks)
    
    # Filter active and likely targets
    targets = [s for s in startups if s["status"] == "active" and s.get("likely_target")]
    
    print(f"\n[*] Found {len(targets)} likely targets:\n")
    
    for s in targets:
        login_icon = "🔐" if s.get("has_login") else "  "
        print(f"  {login_icon} {s['name']:20} | {s['type']:15} | {s['country']:10} | {s['url']}")
    
    # Save to file
    with open("bugbounty/small_startup_targets.json", "w") as f:
        json.dump(targets, f, indent=2)
    
    print(f"\n[*] Saved to bugbounty/small_startup_targets.json")
    
    return targets

if __name__ == "__main__":
    asyncio.run(find_startups())
