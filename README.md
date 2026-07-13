# manula_bugbounty
bugbounty-manula




# Bug Bounty Methodology: Manual Logic Testing
## Solo Operator Guide for Finding Bugs in GET Endpoints & APIs

---

## Table of Contents
1. [Overview](#overview)
2. [Phase 1: Reconnaissance](#phase-1-reconnaissance)
3. [Phase 2: Attack Surface Mapping](#phase-2-attack-surface-mapping)
4. [Phase 3: Manual Logic Testing](#phase-3-manual-logic-testing)
5. [Phase 4: API-Specific Testing](#phase-4-api-specific-testing)
6. [Phase 5: Documentation & Reporting](#phase-5-documentation--reporting)
7. [Tools Checklist](#tools-checklist)
8. [Solo Operator Workflow](#solo-operator-workflow)
9. [Reference: ati.su Case Study](#reference-atisu-case-study)

---

## Overview

This methodology focuses on **manual logic testing** without automated scanners. It's designed for solo bug bounty hunters who want to find high-severity vulnerabilities through careful analysis of application logic, API schemas, and GET endpoint behavior.

**Core Philosophy:**
- Think like a developer, not a scanner
- Understand the business logic before testing
- Manual testing finds what scanners miss
- Quality over quantity

**Target Types:**
- REST APIs with OpenAPI/Swagger documentation
- Web applications with sequential integer IDs
- Authentication flows (OAuth2, password recovery)
- File storage and management systems

---

## Phase 1: Reconnaissance

### Step 1.1: Subdomain Enumeration
```bash
# Passive enumeration
subfinder -d target.com -o subdomains.txt

# Active enumeration
amass enum -passive -d target.com -o amass_results.txt

# Combine and deduplicate
cat subdomains.txt amass_results.txt | sort -u > all_subs.txt
```

### Step 1.2: Live Host Discovery
```bash
# Check which subdomains are live
httpx -l all_subs.txt -o live_hosts.txt -silent

# Get additional info (status codes, titles, tech stack)
httpx -l all_subs.txt -o httpx_results.txt -json
```

### Step 1.3: ASN/IP Range Mapping
```bash
# Find ASN ranges
whois -h whois.radb.net -- '-i origin AS12345' > asn_ranges.txt

# Map IP ranges to subdomains
nmap -sL -iL asn_ranges.txt | grep target.com > ip_mapping.txt
```

### Step 1.4: URL Collection
```bash
# Use multiple tools for comprehensive coverage
katana -u live_hosts.txt -o urls_katana.txt
waybackurls < live_hosts.txt > urls_wayback.txt
gau target.com > urls_gau.txt

# Combine and deduplicate
cat urls_*.txt | sort -u > all_urls.txt
```

### Step 1.5: OpenAPI/Swagger Discovery
```bash
# Common paths to check
for path in \
  "/swagger.json" \
  "/api-docs" \
  "/openapi.json" \
  "/v1/api-docs" \
  "/v2/api-docs" \
  "/swagger-ui.html" \
  "/developers/raw/api/*.openapi.json"; do
  curl -s "https://target.com$path" | head -c 100
done

# Save discovered specs
curl -s "https://target.com/developers/raw/api/trucks.openapi.json" > api_trucks.json
curl -s "https://target.com/developers/raw/api/firms.openapi.json" > api_firms.json
```

### Step 1.6: JavaScript Analysis
```bash
# Find all JS files
grep -E '\.js$' all_urls.txt > js_files.txt

# Extract endpoints from JS
for js in $(cat js_files.txt); do
  curl -s "$js" | grep -oE '/[a-zA-Z0-9/_-]+' >> js_endpoints.txt
done

# Look for secrets/keys in JS
for js in $(cat js_files.txt); do
  curl -s "$js" | grep -iE '(api[_-]?key|secret|token|password)' >> js_secrets.txt
done
```

### Step 1.7: robots.txt & sitemap.xml Analysis
```bash
# Check robots.txt for hidden paths
curl -s "https://target.com/robots.txt" > robots.txt

# Check sitemap.xml
curl -s "https://target.com/sitemap.xml" > sitemap.xml

# Extract URLs from sitemap
grep -oE '<loc>[^<]+</loc>' sitemap.xml | sed 's/<loc>//g;s/<\/loc>//g' > sitemap_urls.txt
```

---

## Phase 2: Attack Surface Mapping

### Step 2.1: Subdomain Categorization
Organize subdomains by function:
- **Authentication:** id.target.com, auth.target.com
- **API:** api.target.com, gw.target.com
- **Files/Storage:** files.target.com, cdn.target.com
- **Forums/Community:** forums.target.com, chat.target.com
- **Admin/Internal:** admin.target.com, help.target.com
- **Content:** news.target.com, academy.target.com

### Step 2.2: Endpoint Classification
For each subdomain, classify endpoints:

**Public Endpoints (No Auth Required):**
```
GET /firms/{id}/passport
GET /developers/raw/api/*.openapi.json
GET /sitemap.xml
GET /robots.txt
```

**Authenticated Endpoints (Auth Required):**
```
GET /v1.1/trucks/*
GET /v2/boards/*
GET /gw/{GUID}/public/v1/storage
```

**Internal Endpoints (Should Not Be Public):**
```
GET /admin/*
GET /internal/*
GET /debug/*
```

### Step 2.3: API Schema Analysis
From OpenAPI specs, identify:

1. **Path Parameters** (potential IDOR):
   - Sequential integers: `{id}`, `{firmId}`, `{atiId}`
   - GUIDs: `{guid}`, `{userId}`
   - String identifiers: `{username}`, `{email}`

2. **Query Parameters** (potential injection):
   - User-controlled: `?next=`, `?redirect=`
   - Pagination: `?page=`, `?limit=`
   - Filtering: `?status=`, `?type=`

3. **Authorization Requirements**:
   - BearerAuth, BasicAuth, OAuth2
   - Public vs authenticated endpoints

### Step 2.4: Parameter Identification
Create a parameter inventory:
```
Endpoint                          Parameter    Type      Potential
----------------------------------------------------------------
GET /firms/{id}/passport          id           int       IDOR
GET /?FirmID={id}                 FirmID       int       IDOR
GET /login/?next={url}            next         string    Injection
GET /gw/{GUID}/public/v1/storage  GUID         string    IDOR
```

---

## Phase 3: Manual Logic Testing

### 3.1: IDOR Testing on GET Endpoints

**Objective:** Access resources belonging to other users by manipulating identifiers.

**Step-by-Step Process:**

1. **Identify Sequential Parameters**
   ```
   Look for: /firms/{id}, /users/{id}, /orders/{id}
   Test with: 1, 100, 1000, 10000, 100000
   ```

2. **Test with Different Auth States**
   ```bash
   # No auth
   curl -s "https://target.com/firms/1/passport"

   # With your auth token
   curl -s -H "Authorization: Bearer YOUR_TOKEN" "https://target.com/firms/1/passport"

   # With different user's token
   curl -s -H "Authorization: Bearer OTHER_USER_TOKEN" "https://target.com/firms/1/passport"
   ```

3. **Check Response Differences**
   - Different HTTP status codes (200 vs 403 vs 401)
   - Different response sizes
   - Different data fields returned

4. **Map Data Leakage**
   ```
   FirmID=1 → GUID=28f9e820 (User manages: 1, 11, 44, 46)
   FirmID=6 → GUID=4c521d17 (User manages: 6, 8, 13, 16, 18, 27, 30, 50)
   ```

**Proof of Concept Template:**
```
IDOR on Firm Passport Pages
Endpoint: GET https://target.com/firms/{id}/passport
Impact: Access to company passports (INN, OGRN, contact info) for any firm

Proof:
- GET /firms/1/passport → 200 OK (returns INN, OGRN, bank details)
- GET /firms/100/passport → 200 OK (returns different firm's data)
- GET /firms/100000/passport → 200 OK (no authorization check)

CVSS: 7.5 (High) - Confidentiality impact
```

### 3.2: Parameter Manipulation

**Objective:** Test how endpoints handle unexpected input values.

**Test Cases:**

1. **Negative ID Testing**
   ```bash
   # Test negative values
   curl -s "https://target.com/trucks/create?ID=-3&Action=Add"

   # Expected: Should reject negative IDs
   # Actual: May accept and create/modify resources
   ```

2. **Parameter Injection**
   ```bash
   # Test unencoded special characters
   curl -s "https://target.com/login/?next=https://target.com/trucks/create?ID=-3&Action=Add"

   # Check if & is parsed correctly
   # If next parameter doesn't encode &, Action becomes separate param
   ```

3. **Type Confusion**
   ```bash
   # Test string where integer expected
   curl -s "https://target.com/firms/abc/passport"

   # Test integer where string expected
   curl -s "https://target.com/users/12345"

   # Test very large numbers
   curl -s "https://target.com/firms/999999999999/passport"
   ```

4. **Missing Parameter Testing**
   ```bash
   # Remove required parameter
   curl -s "https://target.com/firms//passport"

   # Add extra parameters
   curl -s "https://target.com/firms/1/passport?admin=true"
   ```

### 3.3: Authorization Bypass

**Objective:** Access protected resources without proper authentication.

**Test Cases:**

1. **Remove Auth Headers**
   ```bash
   # With auth
   curl -s -H "Authorization: Bearer TOKEN" "https://api.target.com/v1/trucks"

   # Without auth
   curl -s "https://api.target.com/v1/trucks"

   # Check if 200 response is returned
   ```

2. **Test Public vs Private Paths**
   ```bash
   # Test if /public/ prefix bypasses auth
   curl -s "https://api.target.com/gw/{GUID}/public/v1/storage"

   # Test if removing /public/ requires auth
   curl -s "https://api.target.com/gw/{GUID}/v1/storage"
   ```

3. **Token Manipulation**
   ```bash
   # Use expired token
   curl -s -H "Authorization: Bearer EXPIRED_TOKEN" "https://api.target.com/v1/trucks"

   # Use token for different user
   curl -s -H "Authorization: Bearer OTHER_USER_TOKEN" "https://api.target.com/v1/trucks/123"

   # Use empty token
   curl -s -H "Authorization: Bearer " "https://api.target.com/v1/trucks"
   ```

4. **HTTP Method Override**
   ```bash
   # Test if GET endpoint accepts POST
   curl -s -X POST "https://api.target.com/v1/trucks"

   # Test if POST endpoint accepts GET
   curl -s -X GET "https://api.target.com/v1/trucks/create"
   ```

### 3.4: Information Disclosure

**Objective:** Find sensitive information leaked through error messages, responses, or source code.

**Test Cases:**

1. **Error Message Analysis**
   ```bash
   # Test different inputs and compare error messages
   # Registered phone
   curl -s "https://id.target.com/api/v3/password-recovery?phone=%2B7%20916%20123-45-67"

   # Unregistered phone
   curl -s "https://id.target.com/api/v3/password-recovery?phone=%2B7%20667%20898-76-55"

   # Different errors reveal account status
   ```

2. **API Response Comparison**
   ```bash
   # Compare responses with/without auth
   curl -s "https://api.target.com/firms/1" > no_auth.json
   curl -s -H "Authorization: Bearer TOKEN" "https://api.target.com/firms/1" > with_auth.json

   # Check if extra fields are returned with auth
   diff no_auth.json with_auth.json
   ```

3. **Source Code Inspection**
   ```bash
   # Check HTML source for hidden fields
   curl -s "https://target.com/login" | grep -i "hidden\|password\|token"

   # Check JavaScript for API endpoints
   curl -s "https://target.com/app.js" | grep -oE '/api/[a-zA-Z0-9/_-]+'
   ```

4. **OpenAPI Spec Exposure**
   ```bash
   # Access API documentation
   curl -s "https://target.com/developers/raw/api/trucks.openapi.json" | jq .

   # Look for:
   # - Internal endpoints
   # - Deprecated endpoints
   # - Endpoints with weak auth
   ```

### 3.5: Business Logic Testing

**Objective:** Test application workflows for bypasses and logic flaws.

**Test Cases:**

1. **Password Recovery Enumeration**
   ```bash
   # Test different phone numbers
   for phone in "+79161234567" "+76678987655"; do
     curl -s "https://id.target.com/api/v3/password-recovery?phone=$phone"
   done

   # Different responses reveal:
   # - Account exists
   # - Account deleted
   # - Account deactivated
   # - Rate limited
   ```

2. **Workflow Bypass**
   ```bash
   # Skip steps in workflow
   # Normal: Step1 → Step2 → Step3 → Complete
   # Test: Direct access to Step3

   curl -s "https://target.com/order/complete?orderId=123"
   ```

3. **Negative/Zero Value Testing**
   ```bash
   # Test negative quantities
   curl -s "https://target.com/cart/add?item=123&qty=-1"

   # Test zero quantities
   curl -s "https://target.com/cart/add?item=123&qty=0"

   # Test very large quantities
   curl -s "https://target.com/cart/add?item=123&qty=999999999"
   ```

4. **Race Condition Testing**
   ```bash
   # Send multiple requests simultaneously
   for i in {1..10}; do
     curl -s "https://target.com/transfer?from=A&to=B&amount=100" &
   done
   wait
   ```

---

## Phase 4: API-Specific Testing

### 4.1: OpenAPI Spec Analysis

**Download and analyze all available specs:**
```bash
# Download all OpenAPI specs
curl -s "https://target.com/developers/raw/api/trucks.openapi.json" > api_trucks.json
curl -s "https://target.com/developers/raw/api/firms.openapi.json" > api_firms.json
curl -s "https://target.com/developers/raw/api/billing.openapi.json" > api_billing.json

# Analyze for vulnerabilities
for spec in api_*.json; do
  echo "=== Analyzing $spec ==="

  # Find endpoints with path parameters (potential IDOR)
  jq -r '.paths | keys[]' $spec | grep '{'

  # Find endpoints without security requirements
  jq -r '.paths | to_entries[] | .key as $path | .value | to_entries[] | select(.value.security == null) | $path + " " + .key' $spec

  # Find internal/undocumented endpoints
  jq -r '.paths | keys[]' $spec | grep -iE '(admin|internal|debug|test)'
done
```

### 4.2: MCP Server Probing

**Test Model Context Protocol endpoints:**
```bash
# Test MCP endpoint with proper headers
curl -s -X POST "https://api.target.com/gw/panda-mcp/public/v1/mcp" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# Test discovery tools (may work without auth)
curl -s "https://api.target.com/gw/panda-mcp/public/v1/mcp?method=get_spec_info"
curl -s "https://api.target.com/gw/panda-mcp/public/v1/mcp?method=list_categories"
curl -s "https://api.target.com/gw/panda-mcp/public/v1/mcp?method=search_methods"
```

### 4.3: Webhook Key Extraction

**Test webhook authentication:**
```bash
# Try to access webhook status
curl -s "https://api.target.com/webhooks/v1/status/{webhook_id}"

# Check if key is returned in response
# Response may contain: {"hook": {"key": "abc123", "url": "..."}}

# Test if webhook IDs are guessable
for id in {1..1000}; do
  curl -s "https://api.target.com/webhooks/v1/status/$id" | grep -o '"key":"[^"]*"'
done
```

### 4.4: Token Analysis

**Analyze OAuth2 flow:**
```bash
# Check token endpoint
curl -s -X POST "https://api.target.com/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=ID&client_secret=SECRET"

# Check token lifetime (usually 2 hours)
# Check what claims are included
# Test token with different scopes
```

---

## Phase 5: Documentation & Reporting

### 5.1: CVSS Scoring

**Use CVSS v3.1 Calculator:**
- **Critical (9.0-10.0):** Remote code execution, SQL injection, authentication bypass
- **High (7.0-8.9):** IDOR with sensitive data, SSRF, broken authentication
- **Medium (4.0-6.9):** Information disclosure, CSRF, open redirect
- **Low (0.1-3.9):** Missing security headers, verbose errors

### 5.2: Proof of Concept Template

```markdown
### BUG X: [Vulnerability Title] ([Severity])

- **Endpoint:** `GET https://target.com/path/{parameter}`
- **Issue:** [Brief description of the vulnerability]
- **Proof:**
  ```
  Request 1: [First request]
  Response 1: [Response showing vulnerability]

  Request 2: [Second request showing different behavior]
  Response 2: [Response showing impact]
  ```
- **Impact:** [What an attacker could achieve]
- **CVSS Estimate:** [Score] ([Severity]) — [Impact type]
- **Remediation:** [How to fix the issue]
```

### 5.3: Report Structure

```markdown
# Bug Bounty Report — [Target Name]
## Date: [Date]

### Executive Summary
[1-2 sentence summary of findings]

---

## CRITICAL VULNERABILITIES

### BUG 0: [Title]
[Full details using template above]

---

## HIGH VULNERABILITIES
...

---

## TECHNICAL DETAILS

### Live Subdomains
[List of confirmed subdomains]

### API Endpoints
[Discovered endpoints]

### User Data Mapping
[If IDOR found, map users to resources]

---

## RECOMMENDATIONS

### Critical Priority
1. [Fix 1]
2. [Fix 2]

### High Priority
3. [Fix 3]
...
```

---

## Tools Checklist

### Reconnaissance
- [ ] subfinder - Subdomain enumeration
- [ ] httpx - Live host discovery
- [ ] katana - URL crawling
- [ ] waybackurls - Historical URLs
- [ ] amass - ASN/IP mapping

### Manual Testing
- [ ] curl - HTTP requests
- [ ] Burp Suite - Proxy and repeater
- [ ] OWASP ZAP - Alternative proxy
- [ ] browser DevTools - JavaScript analysis

### Analysis
- [ ] jq - JSON parsing
- [ ] grep/ripgrep - Text search
- [ ] python3 - Custom scripts

### Documentation
- [ ] Markdown editor
- [ ] Screenshot tool
- [ ] CVSS calculator

---

## Solo Operator Workflow

### Daily Routine

**Morning (2-3 hours): Reconnaissance**
1. Check for new subdomains
2. Discover new endpoints
3. Download new API specs
4. Update attack surface map

**Afternoon (3-4 hours): Manual Testing**
1. Test high-priority endpoints
2. Perform IDOR testing
3. Test authorization bypass
4. Analyze business logic

**Evening (1-2 hours): Documentation**
1. Write PoCs for findings
2. Calculate CVSS scores
3. Draft reports
4. Submit to bug bounty program

### Prioritization Matrix

| Priority | Criteria | Time Allocation |
|----------|----------|-----------------|
| Critical | Auth bypass, RCE, SQLi | Immediate |
| High | IDOR, SSRF, sensitive data | 2-4 hours |
| Medium | Info disclosure, CSRF | 1-2 hours |
| Low | Missing headers, verbose errors | 30 min |

### Time Management

- **Per Target:** 2-4 weeks
- **Per Endpoint:** 15-30 minutes initial test
- **Per Vulnerability:** 1-2 hours for PoC and report
- **Daily Limit:** 3-4 hours active testing

### Progress Tracking

Create a tracking file:
```markdown
# Testing Progress

## Target: target.com
- [x] Subdomain enumeration (50 subdomains)
- [x] Live host discovery (25 live hosts)
- [x] API spec discovery (10 OpenAPI specs)
- [ ] IDOR testing on /firms/{id}
- [ ] Authorization bypass testing
- [ ] Business logic testing

## Findings
- BUG-001: IDOR on firm passport pages (Critical)
- BUG-002: Password recovery enumeration (High)
- BUG-003: API spec exposure (Medium)
```

---

## Reference: ati.su Case Study

### Discovered Vulnerabilities

**CRITICAL:**
1. User enumeration via password recovery (`id.ati.su/api/v3/password-recovery`)
2. IDOR via FirmID parameter (`trucks.ati.su/?FirmID={id}`)
3. IDOR on firm passport pages (`ati.su/firms/{id}/passport`)

**HIGH:**
4. Parameter injection on login (`id.ati.su/login/?next=`)
5. Exposed user storage endpoints (`ati.su/gw/{GUID}/public/v1/storage`)
6. Public internal document (`news.ati.su/media/files/checklist_pptp.pptx`)

**MEDIUM:**
7. 55+ OpenAPI specs publicly accessible
8. Forum file attachments with GUIDs
9. Negative ID accepted on truck creation

### Key Learnings

1. **OpenAPI specs reveal attack surface** — Always check `/developers/raw/api/*.openapi.json`
2. **Sequential IDs are dangerous** — Test with 1, 100, 1000, 100000
3. **Error messages leak info** — Different errors for different states enable enumeration
4. **Public paths may bypass auth** — Test `/public/` prefix endpoints
5. **User GUIDs are enumerable** — Map users to resources via IDOR

### Tools Used
- subfinder, httpx for recon
- curl for manual testing
- jq for JSON analysis
- Browser DevTools for JS analysis

---

## Quick Reference Card

### IDOR Testing Checklist
- [ ] Identify sequential integer parameters
- [ ] Test with different auth states (none, your token, other user's token)
- [ ] Check response differences (status, size, data)
- [ ] Map data leakage (user → resource mapping)
- [ ] Document with PoC

### Authorization Bypass Checklist
- [ ] Remove auth headers
- [ ] Test public vs private paths
- [ ] Use expired/invalid tokens
- [ ] Test HTTP method override
- [ ] Check for path traversal

### Information Disclosure Checklist
- [ ] Compare error messages for different inputs
- [ ] Analyze API responses with/without auth
- [ ] Inspect JavaScript for hidden endpoints
- [ ] Download and analyze OpenAPI specs
- [ ] Check for exposed admin/internal paths

### Business Logic Checklist
- [ ] Test password recovery enumeration
- [ ] Try workflow bypass (skip steps)
- [ ] Test negative/zero values
- [ ] Check race conditions
- [ ] Test parameter pollution

---

## Final Notes

1. **Manual testing finds what scanners miss** — Logic flaws, IDOR, business logic issues
2. **Understand the application** — Read docs, analyze API specs, understand workflows
3. **Be methodical** — Follow the checklist, document everything
4. **Quality over quantity** — One well-documented Critical beats ten unverified Lows
5. **Respect the program** — Follow scope, don't cause damage, report responsibly

**Happy Hunting!**
