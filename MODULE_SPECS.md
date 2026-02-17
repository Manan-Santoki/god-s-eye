# MODULE_SPECS.md — Detailed Module Specifications

> Every module specification below includes: purpose, input/output format, API details, parsing logic, and Neo4j nodes to create. AI agents must implement each module exactly as specified.

---

## Module Registry & Auto-Discovery

The module registry in `app/modules/__init__.py` must auto-discover all modules:

```python
"""
Auto-discover all BaseModule subclasses.

Implementation:
1. Walk all .py files in app/modules/ recursively
2. Import each module
3. Find all classes that subclass BaseModule
4. Register them by metadata().name
5. Provide: get_module(name), list_modules(), get_modules_for_target(target_type)
"""
```

---

## 1. EMAIL MODULES

### 1.1 `email/validator.py` — Email Format & DNS Validation

| Field | Value |
|---|---|
| Phase | 1 (FAST_API) |
| API Required | None |
| Auth Required | No |
| Rate Limit | N/A (local) |

**Input:** Email address string

**Logic:**
1. Regex validation: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
2. DNS MX record lookup using `dnspython` (verify domain accepts email)
3. SPF record check (TXT record starting with `v=spf1`)
4. DMARC record check (`_dmarc.{domain}` TXT record)
5. Check against known disposable email domains list (maintain list of 3000+ domains)

**Output:**
```json
{
    "is_valid_format": true,
    "has_mx_records": true,
    "mx_records": ["mx1.google.com", "mx2.google.com"],
    "has_spf": true,
    "spf_record": "v=spf1 include:_spf.google.com ~all",
    "has_dmarc": true,
    "dmarc_record": "v=DMARC1; p=reject; rua=...",
    "is_disposable": false,
    "email_provider": "Google Workspace",
    "domain": "example.com"
}
```

**Neo4j:** Create `Email` node, `Domain` node, `(Email)-[:BELONGS_TO]->(Domain)`

---

### 1.2 `email/breach_checker.py` — Multi-Provider Breach Check

| Field | Value |
|---|---|
| Phase | 2 (BREACH_DB) |
| APIs | HIBP, DeHashed, IntelX |
| Auth Required | API keys |
| Rate Limit | HIBP: 1 req/1.5s, DeHashed: varies |

**Input:** Email address

**Logic (per provider):**

**HIBP (Have I Been Pwned):**
- Endpoint: `GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}`
- Headers: `hibp-api-key: {key}`, `user-agent: god_eye`
- Query params: `truncateResponse=false`
- 200 = breaches found (array), 404 = clean
- Also check pastes: `GET /api/v3/pasteaccount/{email}`

**DeHashed:**
- Endpoint: `GET https://api.dehashed.com/search?query=email:{email}`
- Auth: Basic HTTP auth (email:api_key)
- Returns: entries with `email`, `username`, `password`, `hashed_password`, `ip_address`, `name`, `phone`

**IntelX:**
- Endpoint: `POST https://2.intelx.io/intelligent/search`
- Body: `{"term": "{email}", "maxresults": 10, "media": 0, "sort": 2, "terminate": []}`
- Headers: `x-key: {api_key}`
- Two-step: POST to start search, GET results with search ID

**Output:**
```json
{
    "total_breaches": 5,
    "breach_details": [
        {
            "source": "hibp",
            "name": "LinkedIn",
            "breach_date": "2012-05-05",
            "data_classes": ["Email addresses", "Passwords"],
            "is_verified": true,
            "pwn_count": 164611595
        }
    ],
    "paste_appearances": 2,
    "dehashed_records": [
        {
            "email": "user@example.com",
            "username": "user123",
            "hashed_password": "5f4dcc3b...",
            "ip_address": "1.2.3.4",
            "database_name": "LinkedIn"
        }
    ],
    "passwords_exposed": true,
    "earliest_breach": "2012-05-05",
    "latest_breach": "2023-11-15"
}
```

**Neo4j:** Update `Email` node `is_breached=true`, create `Breach` nodes, `(Email)-[:EXPOSED_IN]->(Breach)`

---

### 1.3 `email/hunter.py` — Email Discovery & Verification

| Field | Value |
|---|---|
| Phase | 1 (FAST_API) |
| API | Hunter.io |
| Rate Limit | Free: 25/month, Starter: 500/month |

**Endpoints:**
- Domain search: `GET https://api.hunter.io/v2/domain-search?domain={domain}&api_key={key}`
- Email verify: `GET https://api.hunter.io/v2/email-verifier?email={email}&api_key={key}`
- Email finder: `GET https://api.hunter.io/v2/email-finder?domain={domain}&first_name={first}&last_name={last}&api_key={key}`

**Output:**
```json
{
    "associated_emails": [
        {"email": "john@example.com", "type": "personal", "confidence": 95},
        {"email": "j.doe@company.com", "type": "professional", "confidence": 87}
    ],
    "verification": {
        "status": "valid",
        "score": 95,
        "smtp_check": true,
        "mx_records": true
    },
    "organization": "Example Corp",
    "domain_pattern": "{first}.{last}@example.com"
}
```

---

### 1.4 `email/permutator.py` — Email Permutation Generator

| Field | Value |
|---|---|
| Phase | 1 (FAST_API) |
| API | None (local logic) |

**Logic:** Given a name (e.g., "John Doe") and domain, generate email permutations:
```
john@domain.com, doe@domain.com, johndoe@domain.com, john.doe@domain.com,
j.doe@domain.com, john.d@domain.com, jdoe@domain.com, doej@domain.com,
john_doe@domain.com, john-doe@domain.com
```

Then optionally verify each via Hunter.io or SMTP check.

---

## 2. USERNAME MODULES

### 2.1 `username/sherlock_wrapper.py` — Username Search (400+ sites)

| Field | Value |
|---|---|
| Phase | 1 (FAST_API) |
| API | None (self-hosted CLI tool) |
| Prereq | `pip install sherlock-project` |

**Logic:**
1. Run sherlock as subprocess: `sherlock {username} --json {output_path} --timeout 15`
2. Parse JSON output for found profiles
3. For each found profile, extract: platform name, URL, response time
4. Categorize by platform type: social, professional, creative, gaming, etc.

**Output:**
```json
{
    "username": "manan123",
    "total_found": 23,
    "platforms": [
        {"platform": "GitHub", "url": "https://github.com/manan123", "category": "professional"},
        {"platform": "Instagram", "url": "https://instagram.com/manan123", "category": "social"},
        {"platform": "Reddit", "url": "https://reddit.com/user/manan123", "category": "social"}
    ],
    "not_found": ["TikTok", "LinkedIn", "Snapchat"]
}
```

**Neo4j:** Create `Username` nodes per platform, link `(Person)-[:HAS_ACCOUNT]->(Username)`

---

### 2.2 `username/social_checker.py` — Direct API Verification

| Field | Value |
|---|---|
| Phase | 1 (FAST_API) |
| APIs | GitHub, Reddit, Twitter (public endpoints) |

**Logic (parallel checks):**

**GitHub:** `GET https://api.github.com/users/{username}`
- 200 = exists, extract: name, bio, company, location, public_repos, followers, created_at

**Reddit:** `GET https://www.reddit.com/user/{username}/about.json`
- Headers: custom User-Agent required
- Extract: link_karma, comment_karma, created_utc, subreddit subscribers

**Twitter/X:** `GET https://api.twitter.com/2/users/by/username/{username}`
- Headers: `Authorization: Bearer {token}`
- Extract: name, description, followers_count, tweet_count, created_at, verified

---

## 3. PHONE MODULES

### 3.1 `phone/validator.py` — Phone Number Validation

| Field | Value |
|---|---|
| Phase | 1 (FAST_API) |
| Library | `phonenumbers` (local) |

**Logic:**
```python
import phonenumbers
number = phonenumbers.parse(target, None)  # Auto-detect country
is_valid = phonenumbers.is_valid_number(number)
carrier = phonenumbers.carrier.name_for_number(number, "en")
number_type = phonenumbers.number_type(number)  # MOBILE, FIXED_LINE, VOIP, etc.
country = phonenumbers.region_code_for_number(number)
formatted = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
```

### 3.2 `phone/lookup.py` — Carrier & Reverse Lookup

| Field | Value |
|---|---|
| Phase | 1 (FAST_API) |
| APIs | Numverify, Twilio Lookup |

**Numverify:** `GET http://apilayer.net/api/validate?access_key={key}&number={phone}`

**Twilio Lookup:** `GET https://lookups.twilio.com/v1/PhoneNumbers/{phone}?Type=carrier`
- Auth: Basic (account_sid:auth_token)

---

## 4. WEB SEARCH MODULES

### 4.1 `web/google_cse.py` — Google Custom Search

| Field | Value |
|---|---|
| Phase | 3 (SEARCH_ENGINE) |
| API | Google Custom Search JSON API |
| Rate Limit | Free: 100/day |

**Endpoint:** `GET https://www.googleapis.com/customsearch/v1`
**Params:** `key={api_key}`, `cx={engine_id}`, `q={target}`, `start=1`, `num=10`

**Also run Google Dork queries:**
```
"{target}" site:linkedin.com
"{target}" site:github.com
"{target}" filetype:pdf
"{target}" inurl:resume OR inurl:cv
"{target}" site:pastebin.com
```

### 4.2 `web/wayback.py` — Wayback Machine Archives

| Field | Value |
|---|---|
| Phase | 3 (SEARCH_ENGINE) |
| API | archive.org (free, no key) |

**Endpoints:**
- Availability: `GET https://archive.org/wayback/available?url={target_domain}`
- CDX API: `GET https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=50`
- Snapshot: `GET https://web.archive.org/web/{timestamp}/{url}`

**Logic:** Find historical snapshots, compare changes over time, detect removed content.

---

## 5. SOCIAL MEDIA MODULES (Browser Automation)

### 5.1 `social/linkedin_scraper.py`

| Field | Value |
|---|---|
| Phase | 4 (BROWSER_AUTH) |
| Engine | Playwright |
| Auth | LinkedIn credentials from .env |
| Stealth | Required (LinkedIn aggressively detects bots) |

**Implementation:**
1. Load saved session state from `data/sessions/linkedin_state.json`
2. If no session or expired: perform login flow
   - Navigate to `https://www.linkedin.com/login`
   - Type email (with human delays)
   - Type password (with human delays)
   - Click sign in
   - Handle 2FA/CAPTCHA if detected (log warning, skip)
   - Save session state
3. Search for target: `https://www.linkedin.com/search/results/people/?keywords={target}`
4. For each profile result:
   - Navigate to profile URL
   - Extract: name, headline, current company, location, about section, experience, education, skills, certifications
   - Take screenshot
   - Download profile photo
5. Random delays between pages (3-8 seconds)

**Output:**
```json
{
    "profiles_found": 1,
    "primary_profile": {
        "name": "John Doe",
        "headline": "Software Engineer at Company",
        "location": "San Francisco, CA",
        "current_company": "Company Inc",
        "about": "...",
        "experience": [
            {"title": "SWE", "company": "Company", "duration": "2020-Present"}
        ],
        "education": [
            {"school": "MIT", "degree": "BS Computer Science", "year": "2020"}
        ],
        "skills": ["Python", "Machine Learning"],
        "profile_url": "https://linkedin.com/in/johndoe",
        "profile_image_path": "images/linkedin_profile.jpg",
        "screenshot_path": "screenshots/linkedin_page.png"
    }
}
```

### 5.2 `social/instagram_scraper.py`

| Field | Value |
|---|---|
| Phase | 4 (BROWSER_AUTH) |
| Engine | Playwright |
| Auth | Instagram credentials from .env |

**Implementation:**
1. Login flow similar to LinkedIn
2. Navigate to `https://www.instagram.com/{username}/`
3. Extract: bio, follower count, following count, post count, profile photo
4. Scroll through posts (configurable max, default 50)
5. For each post: image URL, caption, likes, comments, date, location tag
6. Download all images to `images/` directory
7. Extract EXIF data from downloaded images

### 5.3 `social/facebook_scraper.py`

| Field | Value |
|---|---|
| Phase | 4 (BROWSER_AUTH) |
| Engine | Playwright |
| Auth | Facebook credentials from .env |

**Similar pattern to LinkedIn/Instagram. Extract:**
- Profile info, about section, work/education, places lived
- Public posts (text, images, reactions)
- Profile and cover photos

### 5.4 `social/github_api.py`

| Field | Value |
|---|---|
| Phase | 1 (FAST_API) |
| API | GitHub REST API v3 |
| Auth | Personal Access Token (optional but recommended) |
| Rate Limit | 5000 req/hr (authenticated), 60/hr (unauthenticated) |

**Endpoints to query:**
```
GET /users/{username}                    # Profile info
GET /users/{username}/repos?sort=updated  # Repositories
GET /users/{username}/events/public       # Recent activity
GET /users/{username}/gists               # Public gists
GET /users/{username}/followers           # Followers list
GET /users/{username}/following           # Following list
GET /repos/{owner}/{repo}/commits         # Commit history (extract emails!)
```

**Special extraction:** Git commits contain committer email addresses. Fetch commits from recent repos to discover associated emails.

### 5.5 `social/reddit_api.py`

| Field | Value |
|---|---|
| Phase | 1 (FAST_API) |
| API | Reddit OAuth API |
| Auth | Client ID + Secret + User-Agent |
| Rate Limit | 60 req/min |

**OAuth flow:**
```
POST https://www.reddit.com/api/v1/access_token
  grant_type=client_credentials
  → Bearer token
```

**Endpoints:**
```
GET /user/{username}/about          # Profile
GET /user/{username}/submitted      # Posts
GET /user/{username}/comments       # Comments
```

**Analysis:** Extract subreddits frequented, posting patterns, mentioned locations/interests.

---

## 6. DOMAIN & NETWORK MODULES

### 6.1 `domain/dns_recon.py`

| Field | Value |
|---|---|
| Phase | 1 (FAST_API) |
| Library | dnspython (local) |

**Records to query:** A, AAAA, MX, NS, TXT, SOA, CNAME, SRV

**Output includes:** All records, SPF analysis, DMARC policy, email provider detection.

### 6.2 `domain/subdomain_enum.py`

**Three methods combined:**
1. **crt.sh** (free, no key): `GET https://crt.sh/?q=%.{domain}&output=json`
2. **SecurityTrails API**: `GET https://api.securitytrails.com/v1/domain/{domain}/subdomains`
3. **DNS brute force**: Try common subdomain prefixes (www, mail, ftp, dev, staging, api, admin, etc.)

### 6.3 `domain/certificate_search.py`

| Field | Value |
|---|---|
| API | crt.sh (free, no key) |

**Endpoint:** `GET https://crt.sh/?q={domain}&output=json`

Extracts: certificate names, issuer, validity dates, associated domains.

### 6.4 `network/shodan_search.py`

| Field | Value |
|---|---|
| API | Shodan |
| Rate Limit | Free: 1 result/search |

**Endpoints:**
```
GET https://api.shodan.io/shodan/host/{ip}?key={key}      # Host info
GET https://api.shodan.io/dns/resolve?hostnames={domain}&key={key}  # DNS resolve
GET https://api.shodan.io/shodan/host/search?key={key}&query={query}  # Search
```

---

## 7. VISUAL INTELLIGENCE MODULES

### 7.1 `visual/face_recognition.py` — InsightFace

| Field | Value |
|---|---|
| Phase | 5 (IMAGE_PROCESSING) |
| Library | insightface + onnxruntime |
| Model | buffalo_l (auto-downloads on first run) |

**Implementation:**
```python
"""
Face detection and recognition using InsightFace.

Logic:
1. Load the buffalo_l model (downloads ~300MB on first use)
2. For reference image (target):
   - Detect faces
   - Generate 512-dim embedding for each face
3. For each candidate image (scraped from social media):
   - Detect faces
   - Generate embeddings
   - Calculate cosine similarity against reference
   - If similarity > 0.6 → MATCH
   - If similarity > 0.4 → POSSIBLE MATCH
4. Output matches with confidence scores

Usage:
    recognizer = FaceRecognitionModule()
    result = await recognizer.run(
        target="path/to/reference.jpg",
        target_type=TargetType.PERSON,
        context={"discovered_images": ["img1.jpg", "img2.jpg"]}
    )
"""
```

### 7.2 `visual/reverse_image.py` — Multi-Engine Reverse Image Search

**Engines (Playwright-based):**

1. **Google Images:** Navigate to `https://images.google.com`, click camera icon, upload image, parse results
2. **Yandex Images:** Navigate to `https://yandex.com/images/`, upload, parse (best for face matching)
3. **TinEye API:** `POST https://api.tineye.com/rest/search/` with image file

### 7.3 `visual/exif_extractor.py`

**Extract from images using `exifread` and `Pillow`:**
- Camera make/model
- GPS coordinates (convert to address via reverse geocoding)
- Date/time taken
- Software used
- Image dimensions
- Thumbnail extraction

---

## 8. BUSINESS MODULES

### 8.1 `business/opencorporates.py`

| Field | Value |
|---|---|
| API | OpenCorporates |
| Rate Limit | Free: 500/month |

**Endpoint:** `GET https://api.opencorporates.com/v0.4/companies/search?q={company_name}`

**Extract:** Company name, jurisdiction, registration number, status, officers, registered address, filing history.

---

## Module Phase Assignment Summary

| Phase | Modules | Parallelism |
|---|---|---|
| 1 FAST_API | email/validator, email/hunter, email/permutator, username/sherlock, username/social_checker, phone/validator, phone/lookup, domain/dns_recon, domain/certificate_search, social/github_api, social/reddit_api, social/youtube_api | All parallel |
| 2 BREACH_DB | breach/hibp, breach/dehashed, breach/intelx, breach/paste_monitor | All parallel |
| 3 SEARCH_ENGINE | web/google_cse, web/bing_search, web/duckduckgo, web/wayback, web/google_dorker | All parallel |
| 4 BROWSER_AUTH | social/linkedin_scraper, social/instagram_scraper, social/facebook_scraper, social/tiktok_scraper, social/medium_scraper | Semaphore(3) |
| 5 IMAGE_PROC | visual/image_downloader, visual/exif_extractor, visual/reverse_image, visual/face_recognition | Sequential (depends on downloads) |
| 6 DEEP | domain/whois_lookup, domain/subdomain_enum, domain/tech_stack, network/ip_lookup, network/shodan_search, network/censys_search, business/opencorporates | All parallel |
| 7 AI_CORR | ai/correlation_engine, ai/risk_scorer, ai/timeline_builder | Sequential |
| 8 REPORT | ai/report_generator → exporters | Sequential |
