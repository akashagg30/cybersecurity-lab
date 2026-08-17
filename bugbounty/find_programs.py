#!/usr/bin/env python3
"""Find bug bounty programs for startups and SMBs"""
import aiohttp
import asyncio
import json
from typing import List, Dict

# Known startup-friendly programs
STARTUP_PROGRAMS = [
    # Tech startups
    {"name": "Notion", "url": "https://www.notion.so", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "Figma", "url": "https://www.figma.com", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "Linear", "url": "https://linear.app", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "Vercel", "url": "https://vercel.com", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "Supabase", "url": "https://supabase.com", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "Railway", "url": "https://railway.app", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "Render", "url": "https://render.com", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "Fly.io", "url": "https://fly.io", "platform": "HackerOne", "bounty": "Yes"},
    
    # SaaS companies
    {"name": "Loom", "url": "https://www.loom.com", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "Cal.com", "url": "https://cal.com", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "Retool", "url": "https://retool.com", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "PostHog", "url": "https://posthog.com", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "Sentry", "url": "https://sentry.io", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "Auth0", "url": "https://auth0.com", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "MongoDB", "url": "https://www.mongodb.com", "platform": "HackerOne", "bounty": "Yes"},
    
    # Indian startups
    {"name": "Razorpay", "url": "https://razorpay.com", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "Freshworks", "url": "https://freshworks.com", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "Zoho", "url": "https://zoho.com", "platform": "Bugcrowd", "bounty": "Yes"},
    {"name": "Postman", "url": "https://postman.com", "platform": "HackerOne", "bounty": "Yes"},
    {"name": "BrowserStack", "url": "https://browserstack.com", "platform": "HackerOne", "bounty": "Yes"},
]

async def check_program(session: aiohttp.ClientSession, program: Dict) -> Dict:
    """Check if a program is active"""
    try:
        async with session.get(program["url"], timeout=10) as resp:
            program["status"] = "active" if resp.status == 200 else "inactive"
            program["response_code"] = resp.status
    except Exception as e:
        program["status"] = "error"
        program["error"] = str(e)
    
    return program

async def find_programs():
    """Find and verify bug bounty programs"""
    print("=" * 60)
    print("  BUG BOUNTY PROGRAMS FOR STARTUPS/SMBs")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        tasks = [check_program(session, p) for p in STARTUP_PROGRAMS]
        programs = await asyncio.gather(*tasks)
    
    # Filter active programs
    active = [p for p in programs if p["status"] == "active"]
    
    print(f"\n[*] Found {len(active)} active programs:\n")
    
    for p in active:
        print(f"  {p['name']:20} | {p['platform']:12} | {p['url']}")
    
    # Save to file
    with open("bugbounty/programs.json", "w") as f:
        json.dump(active, f, indent=2)
    
    print(f"\n[*] Saved to bugbounty/programs.json")
    
    return active

if __name__ == "__main__":
    asyncio.run(find_programs())
