# ✅ Bug Bounty Checklist

## Before Testing

- [ ] Read program rules and scope
- [ ] Understand what's allowed/prohibited
- [ ] Note bounty ranges and severity definitions
- [ ] Set up testing environment
- [ ] Review previous reports (avoid duplicates)

## Reconnaissance

- [ ] Enumerate subdomains
- [ ] Identify technologies used
- [ ] Map attack surface
- [ ] Find hidden endpoints
- [ ] Check for exposed files (.git, .env, etc.)

## Vulnerability Testing

### Web Application
- [ ] SQL Injection
- [ ] Cross-Site Scripting (XSS)
- [ ] Cross-Site Request Forgery (CSRF)
- [ ] Server-Side Request Forgery (SSRF)
- [ ] File Upload vulnerabilities
- [ ] Path Traversal
- [ ] Authentication bypass
- [ ] Session management issues

### API Security
- [ ] Broken Object Level Authorization (BOLA)
- [ ] Broken Authentication
- [ ] Excessive Data Exposure
- [ ] Lack of Resources & Rate Limiting
- [ ] Broken Function Level Authorization
- [ ] Mass Assignment
- [ ] Security Misconfiguration

### Infrastructure
- [ ] SSL/TLS misconfigurations
- [ ] Missing security headers
- [ ] Server information disclosure
- [ ] Exposed admin panels
- [ ] Default credentials

## Validation

- [ ] Verify each finding is real
- [ ] Test with different payloads
- [ ] Check edge cases
- [ ] Document reproduction steps
- [ ] Capture screenshots/evidence

## Reporting

- [ ] Write clear title
- [ ] Provide step-by-step reproduction
- [ ] Explain impact
- [ ] Suggest remediation
- [ ] Include evidence (screenshots, requests)
- [ ] Follow report template
- [ ] One vulnerability per report

## Submission

- [ ] Check report quality
- [ ] Verify it's within scope
- [ ] Submit to correct platform
- [ ] Monitor for triage response
- [ ] Respond to questions promptly

## After Submission

- [ ] Track report status
- [ ] Provide additional info if requested
- [ ] Learn from rejections
- [ ] Build reputation
- [ ] Move to next target

---

*Remember: Quality over quantity. One well-written report > ten poor ones.*
