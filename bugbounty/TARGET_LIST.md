# 🎯 Bug Bounty Target List (Verified — XSS In-Scope)

**Last Updated:** August 18, 2026
**Status:** All programs verified to accept XSS as in-scope

---

## ⚠️ Important Notes

1. **XSS is OUT OF SCOPE for Cal.com** — Do NOT submit XSS reports to Cal.com
2. **Always read the scope document** before testing any target
3. **Only test within authorized scope** — testing out of scope is illegal
4. **Quality > Quantity** — One well-documented finding > ten poor reports

---

## 🟢 Tier 1: Beginner-Friendly (Recommended First Targets)

| Program | Platform | Bounty Range | XSS Status | Why Start Here |
|---------|----------|-------------|------------|----------------|
| **Notion** | HackerOne | $100-$10,000 | ✅ In Scope | Good documentation, responsive team |
| **Linear** | HackerOne | $100-$5,000 | ✅ In Scope | Modern tech stack, startup-friendly |
| **PostHog** | HackerOne | $100-$5,000 | ✅ In Scope | Open source, startup-friendly |
| **GitLab** | HackerOne | $100-$20,000 | ✅ In Scope | Large scope, well-documented |
| **Railway** | HackerOne | $100-$5,000 | ✅ In Scope | Cloud platform, modern stack |

---

## 🟡 Tier 2: Mid-Size Companies

| Program | Platform | Bounty Range | XSS Status | Notes |
|---------|----------|-------------|------------|-------|
| **Shopify** | HackerOne | $500-$30,000 | ✅ In Scope | Large scope, e-commerce |
| **Slack** | HackerOne | $100-$10,000 | ✅ In Scope | Collaboration platform |
| **GitHub** | HackerOne | $100-$20,000 | ✅ In Scope | Developer tools |
| **Vercel** | HackerOne | $100-$5,000 | ✅ In Scope | Deployment platform |
| **Dropbox** | Bugcrowd | $100-$10,000 | ✅ In Scope | Cloud storage |

---

## 🔴 Tier 3: Enterprise (Higher Bounties, More Competition)

| Program | Platform | Bounty Range | XSS Status | Notes |
|---------|----------|-------------|------------|-------|
| **Autodesk** | Bugcrowd | $500-$20,000 | ✅ In Scope | CAD/design software |
| **Atlassian** | Bugcrowd | $100-$10,000 | ✅ In Scope | Jira, Confluence |
| **Twitch** | Bugcrowd | $100-$10,000 | ✅ In Scope | Streaming platform |
| **Spotify** | Bugcrowd | $100-$10,000 | ✅ In Scope | Music platform |

---

## 🚫 Do NOT Test (Out of Scope or Conflicts)

| Target | Reason |
|--------|--------|
| **Cal.com** | XSS explicitly listed as OUT OF SCOPE |
| **Groww** | Conflict of interest (you have portfolio data) |
| **Parspec** | Employer — never test employer systems |
| **oneresume.life** | Your own domain — fix, don't bounty |

---

## 📋 Testing Workflow

### Step 1: Choose a Target
```
1. Pick from Tier 1 (beginner-friendly)
2. Read their scope document on HackerOne/Bugcrowd
3. Understand what's in-scope and out-of-scope
4. Create an account if you don't have one
```

### Step 2: Reconnaissance
```bash
cd ~/cybersecurity-lab
python cybersec.py recon --domain TARGET.com -v
```

### Step 3: Web Vulnerability Scanning
```bash
python cybersec.py web --target http://TARGET.com -d 3
```

### Step 4: Manual Testing
```
1. Focus on input fields (search, forms, URLs)
2. Test for reflected XSS via URL parameters
3. Test for stored XSS via form submissions
4. Test for DOM-based XSS via JavaScript
```

### Step 5: Document Findings
```
1. Take screenshots of the vulnerability
2. Document steps to reproduce
3. Create a proof-of-concept payload
4. Assess impact and severity
```

### Step 6: Submit Report
```
1. Use the report template: bugbounty/report_template.md
2. Be professional and clear
3. Include all evidence
4. Wait for triage response
```

---

## 🎯 Quick Start: First Target Recommendation

**Start with Notion** on HackerOne:
1. Go to https://hackerone.com/notion
2. Read the scope document
3. Focus on input fields and URL parameters
4. Test for reflected XSS first (easiest to find)
5. Document everything with screenshots

**Expected timeline:**
- Week 1: Recon and initial testing
- Week 2: Manual testing and finding vulnerabilities
- Week 3: Writing and submitting reports
- Week 4: Waiting for triage response

---

## 📊 Success Metrics

Track your progress:
- [ ] Created HackerOne account
- [ ] Completed first recon on Notion
- [ ] Found first potential vulnerability
- [ ] Submitted first report
- [ ] Received first triage response
- [ ] Got first bounty payment

---

*Remember: Quality over quantity. One great report > ten poor ones.*
