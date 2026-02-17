# API_REFERENCE.md — External API Reference

> Complete reference for all external APIs used by GOD_EYE. Organized by category with endpoints, authentication, pricing, rate limits, and response formats.

---

## API Key Availability Check

At startup, the orchestrator checks which API keys are configured in `.env`. Modules that require unavailable keys are automatically **skipped** (not failed). The CLI displays which modules are available vs skipped.

---

## 1. EMAIL & BREACH INTELLIGENCE

### Have I Been Pwned (HIBP)

| Field | Value |
|---|---|
| Base URL | `https://haveibeenpwned.com/api/v3` |
| Auth | Header: `hibp-api-key: {HIBP_API_KEY}` |
| Pricing | Free rate-limited, $3.50/month for higher limits |
| Rate Limit | 1 request per 1.5 seconds (free tier) |
| Env Var | `HIBP_API_KEY` |

**Endpoints:**
```
GET /breachedaccount/{email}?truncateResponse=false
  → 200: Array of breach objects
  → 404: Email not found in breaches

GET /pasteaccount/{email}
  → 200: Array of paste objects
  → 404: Email not found in pastes

GET /breach/{name}
  → 200: Detailed breach info
```

**Required headers:** `hibp-api-key`, `user-agent` (must be set, not empty)

**Response (breach):**
```json
{
    "Name": "LinkedIn",
    "Title": "LinkedIn",
    "Domain": "linkedin.com",
    "BreachDate": "2012-05-05",
    "PwnCount": 164611595,
    "Description": "...",
    "DataClasses": ["Email addresses", "Passwords"],
    "IsVerified": true,
    "IsSensitive": false
}
```

---

### DeHashed

| Field | Value |
|---|---|
| Base URL | `https://api.dehashed.com` |
| Auth | Basic HTTP Auth: `email:api_key` |
| Pricing | $0.01 per query (pay-as-you-go), subscriptions available |
| Rate Limit | Varies by plan |
| Env Var | `DEHASHED_API_KEY` |

**Endpoint:**
```
GET /search?query=email:{email}
GET /search?query=username:{username}
GET /search?query=name:{name}

Headers:
  Accept: application/json
  Authorization: Basic base64(email:api_key)
```

**Response:**
```json
{
    "total": 12,
    "entries": [
        {
            "email": "user@example.com",
            "username": "user123",
            "password": "***",
            "hashed_password": "5f4dcc3b5aa765d61d8327deb882cf99",
            "name": "John Doe",
            "ip_address": "1.2.3.4",
            "phone": "+1234567890",
            "database_name": "LinkedIn_2012"
        }
    ]
}
```

---

### Intelligence X (IntelX)

| Field | Value |
|---|---|
| Base URL | `https://2.intelx.io` |
| Auth | Header: `x-key: {INTELX_API_KEY}` |
| Pricing | Free: limited searches, Paid: from $2/day |
| Env Var | `INTELX_API_KEY` |

**Two-step search:**
```
Step 1: POST /intelligent/search
Body: {"term": "{target}", "maxresults": 10, "media": 0, "sort": 2, "terminate": []}
→ Returns: {"id": "search-uuid"}

Step 2: GET /intelligent/search/result?id={search-uuid}
→ Returns: {"records": [...], "status": 0}
```

---

### Hunter.io

| Field | Value |
|---|---|
| Base URL | `https://api.hunter.io/v2` |
| Auth | Query param: `api_key={HUNTER_IO_API_KEY}` |
| Pricing | Free: 25 req/month, Starter: $49/month (500), Growth: $99/month (5000) |
| Env Var | `HUNTER_IO_API_KEY` |

**Endpoints:**
```
GET /domain-search?domain={domain}&api_key={key}
GET /email-verifier?email={email}&api_key={key}
GET /email-finder?domain={domain}&first_name={first}&last_name={last}&api_key={key}
```

---

### EmailRep.io

| Field | Value |
|---|---|
| Base URL | `https://emailrep.io` |
| Auth | Header: `Key: {EMAILREP_API_KEY}` (optional for free tier) |
| Pricing | Free tier available |
| Env Var | `EMAILREP_API_KEY` |

**Endpoint:**
```
GET /{email}
Headers: Key: {api_key}, User-Agent: god_eye
```

---

## 2. SEARCH ENGINES

### Google Custom Search JSON API

| Field | Value |
|---|---|
| Base URL | `https://www.googleapis.com/customsearch/v1` |
| Auth | Query param: `key={GOOGLE_CSE_API_KEY}` |
| Pricing | Free: 100 queries/day, Paid: $5 per 1000 queries |
| Rate Limit | 100/day free |
| Env Vars | `GOOGLE_CSE_API_KEY`, `GOOGLE_CSE_ENGINE_ID` |

**Endpoint:**
```
GET /customsearch/v1?key={key}&cx={engine_id}&q={query}&start={offset}&num=10
```

**Pagination:** `start` param (1, 11, 21, ...) for next pages. Max 100 results total.

---

### Bing Web Search API

| Field | Value |
|---|---|
| Base URL | `https://api.bing.microsoft.com/v7.0/search` |
| Auth | Header: `Ocp-Apim-Subscription-Key: {BING_API_KEY}` |
| Pricing | Free: 1000 transactions/month, S1: $7/1000 |
| Env Var | `BING_API_KEY` |

---

### DuckDuckGo Instant Answer API

| Field | Value |
|---|---|
| Base URL | `https://api.duckduckgo.com/` |
| Auth | None required |
| Pricing | FREE |
| Rate Limit | Be respectful (add delays) |

**Endpoint:**
```
GET /?q={query}&format=json&no_html=1&skip_disambig=1
```

---

### Wayback Machine / Internet Archive

| Field | Value |
|---|---|
| Base URL | `https://archive.org` / `https://web.archive.org` |
| Auth | None required |
| Pricing | FREE |

**Endpoints:**
```
GET https://archive.org/wayback/available?url={url}
GET https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=50&fl=timestamp,original,statuscode
```

---

## 3. SOCIAL MEDIA APIs

### GitHub REST API v3

| Field | Value |
|---|---|
| Base URL | `https://api.github.com` |
| Auth | Header: `Authorization: Bearer {GITHUB_TOKEN}` |
| Pricing | FREE |
| Rate Limit | 5000 req/hr (auth), 60/hr (unauth) |
| Env Var | `GITHUB_TOKEN` |

**Key endpoints:**
```
GET /users/{username}
GET /users/{username}/repos?sort=updated&per_page=30
GET /users/{username}/events/public
GET /users/{username}/gists
GET /repos/{owner}/{repo}/commits?per_page=30
GET /search/users?q={query}
GET /search/code?q={query}+user:{username}
```

---

### Reddit OAuth API

| Field | Value |
|---|---|
| Token URL | `https://www.reddit.com/api/v1/access_token` |
| API Base | `https://oauth.reddit.com` |
| Auth | OAuth2 Client Credentials |
| Rate Limit | 60 requests/minute |
| Env Vars | `REDDIT_CLIENT_ID`, `REDDIT_CLIENT_SECRET` |

**OAuth flow:**
```
POST https://www.reddit.com/api/v1/access_token
  Authorization: Basic base64({client_id}:{client_secret})
  Content-Type: application/x-www-form-urlencoded
  Body: grant_type=client_credentials
```

**Endpoints:**
```
GET /user/{username}/about
GET /user/{username}/submitted?limit=100
GET /user/{username}/comments?limit=100
```

---

### Twitter/X API v2

| Field | Value |
|---|---|
| Base URL | `https://api.twitter.com/2` |
| Auth | Header: `Authorization: Bearer {TWITTER_BEARER_TOKEN}` |
| Pricing | Free: 1500 tweets/month read, Basic: $100/month |
| Env Var | `TWITTER_BEARER_TOKEN` |

**Endpoints:**
```
GET /users/by/username/{username}?user.fields=description,public_metrics,created_at,profile_image_url,verified
GET /users/{id}/tweets?max_results=100&tweet.fields=created_at,public_metrics,geo
```

---

### YouTube Data API v3

| Field | Value |
|---|---|
| Base URL | `https://www.googleapis.com/youtube/v3` |
| Auth | Query param: `key={YOUTUBE_API_KEY}` |
| Pricing | Free: 10,000 units/day |
| Env Var | `YOUTUBE_API_KEY` |

**Endpoints:**
```
GET /search?part=snippet&q={query}&type=channel&key={key}
GET /channels?part=snippet,statistics&id={channel_id}&key={key}
GET /search?part=snippet&channelId={id}&type=video&maxResults=50&key={key}
```

---

## 4. DOMAIN & NETWORK

### WhoisXML API

| Field | Value |
|---|---|
| Base URL | `https://www.whoisxmlapi.com/whoisserver` |
| Auth | Query param: `apiKey={WHOISXML_API_KEY}` |
| Pricing | Free: 500 credits/month, Paid: from $19.99/month |
| Env Var | `WHOISXML_API_KEY` |

**Endpoint:**
```
GET /WhoisService?apiKey={key}&domainName={domain}&outputFormat=JSON
```

---

### SecurityTrails

| Field | Value |
|---|---|
| Base URL | `https://api.securitytrails.com/v1` |
| Auth | Header: `APIKEY: {SECURITYTRAILS_API_KEY}` |
| Pricing | Free: 50 API calls/month |
| Env Var | `SECURITYTRAILS_API_KEY` |

**Endpoints:**
```
GET /domain/{domain}
GET /domain/{domain}/subdomains
GET /history/{domain}/dns/a
```

---

### Shodan

| Field | Value |
|---|---|
| Base URL | `https://api.shodan.io` |
| Auth | Query param: `key={SHODAN_API_KEY}` |
| Pricing | Free: limited, Lifetime: $59 |
| Env Var | `SHODAN_API_KEY` |

**Endpoints:**
```
GET /shodan/host/{ip}?key={key}
GET /dns/resolve?hostnames={domains}&key={key}
GET /shodan/host/search?key={key}&query={query}
```

---

### crt.sh (Certificate Transparency)

| Field | Value |
|---|---|
| Base URL | `https://crt.sh` |
| Auth | None |
| Pricing | FREE |

**Endpoint:**
```
GET /?q={domain}&output=json
GET /?q=%.{domain}&output=json    # Wildcard subdomain search
```

---

### IPinfo.io

| Field | Value |
|---|---|
| Base URL | `https://ipinfo.io` |
| Auth | Header: `Authorization: Bearer {IPINFO_TOKEN}` |
| Pricing | Free: 50,000 req/month |
| Env Var | `IPINFO_TOKEN` |

**Endpoint:**
```
GET /{ip}?token={token}
GET /{ip}/json
```

---

### VirusTotal

| Field | Value |
|---|---|
| Base URL | `https://www.virustotal.com/api/v3` |
| Auth | Header: `x-apikey: {VIRUSTOTAL_API_KEY}` |
| Pricing | Free: 4 req/min, 500 req/day |
| Env Var | `VIRUSTOTAL_API_KEY` |

**Endpoints:**
```
GET /domains/{domain}
GET /ip_addresses/{ip}
GET /urls/{base64_url}
```

---

### AbuseIPDB

| Field | Value |
|---|---|
| Base URL | `https://api.abuseipdb.com/api/v2` |
| Auth | Header: `Key: {ABUSEIPDB_API_KEY}` |
| Pricing | Free: 1000 req/day |
| Env Var | `ABUSEIPDB_API_KEY` |

**Endpoint:**
```
GET /check?ipAddress={ip}&maxAgeInDays=90
```

---

## 5. PHONE INTELLIGENCE

### Numverify

| Field | Value |
|---|---|
| Base URL | `http://apilayer.net/api` |
| Auth | Query param: `access_key={NUMVERIFY_API_KEY}` |
| Pricing | Free: 100 req/month |
| Env Var | `NUMVERIFY_API_KEY` |

**Endpoint:**
```
GET /validate?access_key={key}&number={phone}&country_code=&format=1
```

---

### Twilio Lookup

| Field | Value |
|---|---|
| Base URL | `https://lookups.twilio.com/v1` |
| Auth | Basic Auth: `{TWILIO_ACCOUNT_SID}:{TWILIO_AUTH_TOKEN}` |
| Pricing | $0.005 per lookup |
| Env Vars | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` |

**Endpoint:**
```
GET /PhoneNumbers/{phone}?Type=carrier
```

---

## 6. IMAGE INTELLIGENCE

### TinEye API

| Field | Value |
|---|---|
| Base URL | `https://api.tineye.com/rest` |
| Auth | API key in request |
| Pricing | From $200/year (5000 searches) |
| Env Var | `TINEYE_API_KEY` |

**Endpoint:**
```
POST /search/
  Content-Type: multipart/form-data
  image: {file}
  api_key: {key}
```

---

### Google Cloud Vision API

| Field | Value |
|---|---|
| Base URL | `https://vision.googleapis.com/v1` |
| Auth | Query param or OAuth |
| Pricing | Free: 1000 units/month |
| Env Var | `GOOGLE_VISION_API_KEY` |

**Endpoint:**
```
POST /images:annotate?key={key}
Body: {
    "requests": [{
        "image": {"content": "{base64_image}"},
        "features": [
            {"type": "FACE_DETECTION"},
            {"type": "WEB_DETECTION"},
            {"type": "TEXT_DETECTION"}
        ]
    }]
}
```

---

## 7. BUSINESS INTELLIGENCE

### OpenCorporates

| Field | Value |
|---|---|
| Base URL | `https://api.opencorporates.com/v0.4` |
| Auth | Query param: `api_token={OPENCORPORATES_API_TOKEN}` |
| Pricing | Free: 500 req/month |
| Env Var | `OPENCORPORATES_API_TOKEN` |

**Endpoints:**
```
GET /companies/search?q={company_name}&api_token={token}
GET /companies/{jurisdiction_code}/{company_number}?api_token={token}
GET /officers/search?q={person_name}&api_token={token}
```

---

## 8. AI PROVIDERS

### Anthropic (Claude)

| Field | Value |
|---|---|
| Base URL | `https://api.anthropic.com/v1` |
| Auth | Header: `x-api-key: {ANTHROPIC_API_KEY}` |
| Env Var | `ANTHROPIC_API_KEY` |

**Use the `anthropic` Python SDK:**
```python
from anthropic import AsyncAnthropic
client = AsyncAnthropic(api_key=settings.anthropic_api_key)
response = await client.messages.create(
    model=settings.ai_model,
    max_tokens=settings.ai_max_tokens,
    messages=[{"role": "user", "content": prompt}]
)
```

### OpenAI (GPT)

| Field | Value |
|---|---|
| Auth | Header: `Authorization: Bearer {OPENAI_API_KEY}` |
| Env Var | `OPENAI_API_KEY` |

**Use the `openai` Python SDK.**

### Ollama (Self-Hosted)

| Field | Value |
|---|---|
| Base URL | `http://localhost:11434` (default) |
| Auth | None |
| Env Vars | `OLLAMA_ENDPOINT`, `OLLAMA_MODEL` |

**Endpoint:**
```
POST /api/generate
Body: {"model": "{model}", "prompt": "{prompt}", "stream": false}
```

---

## Cost Summary

| Budget Tier | Monthly Cost | APIs Included |
|---|---|---|
| **Free** | $0 | HIBP (limited), GitHub, Reddit, DuckDuckGo, Wayback, crt.sh, IPinfo, AbuseIPDB, Sherlock, Ollama |
| **Basic** | ~$60-100 | + Hunter.io ($49), Numverify ($10), Google CSE (free 100/day) |
| **Professional** | ~$300-500 | + DeHashed, Twitter API ($100), SecurityTrails ($99), Shodan ($59 lifetime) |
| **Enterprise** | ~$700-1000+ | + Censys, VirusTotal Premium, TinEye, Clearbit, IPinfo paid |

**Recommendation:** Start with Free tier. Add APIs incrementally as needed. Shodan lifetime ($59) is excellent value.
