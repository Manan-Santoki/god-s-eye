# DATABASE_SCHEMA.md — Data Models & Storage

---

## 1. Neo4j Graph Database Schema

### Node Labels & Properties

```cypher
// ── Person (Central Entity) ──
(:Person {
    id: STRING,              // UUID
    name: STRING,            // Full name
    aliases: [STRING],       // Known aliases/nicknames
    age: INTEGER,            // If discovered
    gender: STRING,          // If discovered
    risk_score: FLOAT,       // 0.0-10.0
    first_seen: DATETIME,    // When first discovered in this scan
    request_id: STRING       // Which scan created this
})

// ── Username (Social Account) ──
(:Username {
    id: STRING,              // UUID
    handle: STRING,          // The username string
    platform: STRING,        // "github", "reddit", "linkedin", etc.
    profile_url: STRING,     // Full URL to profile
    is_verified: BOOLEAN,    // Platform verification status
    follower_count: INTEGER,
    following_count: INTEGER,
    bio: STRING,
    created_at: DATETIME,    // Account creation date
    last_active: DATETIME,   // Last post/activity date
    profile_image_path: STRING, // Local path to downloaded image
    screenshot_path: STRING,    // Local path to screenshot
    raw_data: STRING         // JSON string of full scraped data
})

// ── Email ──
(:Email {
    id: STRING,
    address: STRING,         // email@example.com
    domain: STRING,          // example.com
    is_valid: BOOLEAN,       // MX record exists
    is_breached: BOOLEAN,    // Found in any breach DB
    breach_count: INTEGER,   // Number of breaches
    is_disposable: BOOLEAN,  // Temporary email service
    reputation_score: FLOAT, // 0.0-1.0 from EmailRep
    provider: STRING         // "Google", "Microsoft", "ProtonMail", etc.
})

// ── Phone ──
(:Phone {
    id: STRING,
    number: STRING,          // E.164 format: +1234567890
    country_code: STRING,    // "US", "IN", etc.
    carrier: STRING,         // "Verizon", "Jio", etc.
    line_type: STRING,       // "mobile", "landline", "voip"
    is_valid: BOOLEAN
})

// ── Domain ──
(:Domain {
    id: STRING,
    name: STRING,            // example.com
    registrar: STRING,
    registration_date: DATETIME,
    expiration_date: DATETIME,
    registrant_name: STRING, // WHOIS registrant (if not private)
    registrant_org: STRING,
    nameservers: [STRING],
    has_whois_privacy: BOOLEAN,
    tech_stack: [STRING]     // ["nginx", "React", "CloudFlare"]
})

// ── IP Address ──
(:IP {
    id: STRING,
    address: STRING,         // "1.2.3.4"
    version: INTEGER,        // 4 or 6
    isp: STRING,
    organization: STRING,
    asn: STRING,
    is_vpn: BOOLEAN,
    is_tor: BOOLEAN,
    is_proxy: BOOLEAN,
    abuse_score: INTEGER,    // AbuseIPDB confidence
    open_ports: [INTEGER]    // From Shodan
})

// ── Location ──
(:Location {
    id: STRING,
    latitude: FLOAT,
    longitude: FLOAT,
    address: STRING,         // Full address string
    city: STRING,
    state: STRING,
    country: STRING,
    country_code: STRING,
    source: STRING           // "ip_geolocation", "exif", "social_profile", "whois"
})

// ── Image ──
(:Image {
    id: STRING,
    file_path: STRING,       // Local path
    original_url: STRING,    // Where it was found
    source_platform: STRING, // "instagram", "linkedin", etc.
    hash_md5: STRING,        // For deduplication
    hash_perceptual: STRING, // For visual similarity
    width: INTEGER,
    height: INTEGER,
    has_faces: BOOLEAN,
    face_count: INTEGER,
    has_exif: BOOLEAN,
    has_gps: BOOLEAN,
    captured_at: DATETIME    // EXIF date if available
})

// ── Breach ──
(:Breach {
    id: STRING,
    name: STRING,            // "LinkedIn", "Adobe"
    domain: STRING,
    breach_date: DATE,
    pwn_count: INTEGER,
    data_classes: [STRING],  // ["Emails", "Passwords", "Phone numbers"]
    is_verified: BOOLEAN,
    is_sensitive: BOOLEAN,
    source: STRING           // "hibp", "dehashed", "intelx"
})

// ── Company ──
(:Company {
    id: STRING,
    name: STRING,
    domain: STRING,
    industry: STRING,
    employee_count: STRING,  // Range: "51-200"
    jurisdiction: STRING,
    registration_number: STRING,
    status: STRING,          // "Active", "Dissolved"
    incorporated_date: DATE
})

// ── Certificate ──
(:Certificate {
    id: STRING,
    serial_number: STRING,
    issuer: STRING,          // "Let's Encrypt", "DigiCert"
    common_name: STRING,
    san_domains: [STRING],   // Subject Alternative Names
    not_before: DATETIME,
    not_after: DATETIME
})

// ── Subdomain ──
(:Subdomain {
    id: STRING,
    name: STRING,            // "api.example.com"
    ip_addresses: [STRING],
    is_alive: BOOLEAN
})

// ── Post (Social Media Content) ──
(:Post {
    id: STRING,
    platform: STRING,
    content: STRING,         // Text content
    url: STRING,
    posted_at: DATETIME,
    likes: INTEGER,
    comments: INTEGER,
    shares: INTEGER,
    has_image: BOOLEAN,
    has_location: BOOLEAN
})
```

### Relationships

```cypher
// Person connections
(Person)-[:HAS_ACCOUNT]->(Username)
(Person)-[:HAS_EMAIL]->(Email)
(Person)-[:HAS_PHONE]->(Phone)
(Person)-[:WORKS_AT {role: STRING, since: DATE}]->(Company)
(Person)-[:LOCATED_AT {confidence: FLOAT}]->(Location)
(Person)-[:APPEARS_IN {similarity: FLOAT}]->(Image)

// Username connections
(Username)-[:USED_EMAIL]->(Email)
(Username)-[:FOLLOWS]->(Username)
(Username)-[:FOLLOWED_BY]->(Username)
(Username)-[:POSTED]->(Post)
(Username)-[:PROFILE_IMAGE]->(Image)

// Email connections
(Email)-[:BELONGS_TO_DOMAIN]->(Domain)
(Email)-[:EXPOSED_IN]->(Breach)

// Domain connections
(Domain)-[:RESOLVES_TO]->(IP)
(Domain)-[:HAS_SUBDOMAIN]->(Subdomain)
(Domain)-[:HAS_CERTIFICATE]->(Certificate)
(Domain)-[:OWNED_BY]->(Company)

// IP connections
(IP)-[:LOCATED_AT]->(Location)
(IP)-[:HOSTS]->(Domain)

// Image connections
(Image)-[:FOUND_ON]->(Username)  // Which platform
(Image)-[:TAKEN_AT]->(Location)  // EXIF GPS
(Image)-[:CONTAINS_FACE {similarity: FLOAT}]->(Person)

// Post connections
(Post)-[:MENTIONS]->(Person)
(Post)-[:TAGGED_AT]->(Location)
(Post)-[:CONTAINS]->(Image)

// Subdomain connections
(Subdomain)-[:RESOLVES_TO]->(IP)
```

### Neo4j Indexes (Create at Startup)

```cypher
CREATE INDEX person_name IF NOT EXISTS FOR (p:Person) ON (p.name);
CREATE INDEX email_address IF NOT EXISTS FOR (e:Email) ON (e.address);
CREATE INDEX username_handle IF NOT EXISTS FOR (u:Username) ON (u.handle);
CREATE INDEX username_platform IF NOT EXISTS FOR (u:Username) ON (u.platform);
CREATE INDEX domain_name IF NOT EXISTS FOR (d:Domain) ON (d.name);
CREATE INDEX ip_address IF NOT EXISTS FOR (i:IP) ON (i.address);
CREATE INDEX image_hash IF NOT EXISTS FOR (img:Image) ON (img.hash_md5);
CREATE INDEX breach_name IF NOT EXISTS FOR (b:Breach) ON (b.name);
CREATE CONSTRAINT person_id IF NOT EXISTS FOR (p:Person) REQUIRE p.id IS UNIQUE;
CREATE CONSTRAINT email_id IF NOT EXISTS FOR (e:Email) REQUIRE e.id IS UNIQUE;
```

### Useful Cypher Queries

```cypher
// Get full graph for a target
MATCH (p:Person {name: $target})-[r*1..3]-(connected)
RETURN p, r, connected

// Find all breaches for a person's emails
MATCH (p:Person)-[:HAS_EMAIL]->(e:Email)-[:EXPOSED_IN]->(b:Breach)
WHERE p.name = $target
RETURN e.address, collect(b.name) AS breaches

// Find cross-platform connections
MATCH (u1:Username)-[:FOLLOWS]->(u2:Username)
WHERE u1.platform <> u2.platform
RETURN u1, u2

// Calculate risk factors
MATCH (p:Person {name: $target})
OPTIONAL MATCH (p)-[:HAS_EMAIL]->(e:Email)-[:EXPOSED_IN]->(b:Breach)
OPTIONAL MATCH (p)-[:HAS_ACCOUNT]->(u:Username)
OPTIONAL MATCH (p)-[:APPEARS_IN]->(img:Image)
RETURN p.name,
       count(DISTINCT b) AS breach_count,
       count(DISTINCT u) AS platform_count,
       count(DISTINCT img) AS image_count
```

---

## 2. SQLite Cache Schema

**Database:** `data/cache/osint_cache.db`

```sql
-- API response cache (avoid duplicate requests)
CREATE TABLE IF NOT EXISTS api_cache (
    cache_key TEXT PRIMARY KEY,        -- "{module}:{target}:{params_hash}"
    response_json TEXT NOT NULL,       -- Cached JSON response
    status_code INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,     -- created_at + TTL
    hit_count INTEGER DEFAULT 0        -- Track cache usage
);

CREATE INDEX idx_cache_expires ON api_cache(expires_at);

-- Rate limit tracking per domain
CREATE TABLE IF NOT EXISTS rate_limits (
    domain TEXT PRIMARY KEY,
    request_count INTEGER DEFAULT 0,
    window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    window_size_seconds INTEGER DEFAULT 60,
    max_requests INTEGER DEFAULT 60
);

-- Scan history
CREATE TABLE IF NOT EXISTS scans (
    request_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    status TEXT DEFAULT 'pending',     -- pending, running, paused, completed, failed
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    modules_executed TEXT,             -- JSON array of module names
    modules_failed TEXT,               -- JSON array of failed module names
    total_findings INTEGER DEFAULT 0,
    risk_score REAL,
    metadata_json TEXT                 -- Full metadata as JSON
);

CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_target ON scans(target);

-- Audit log (append-only, never delete)
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,              -- "scan_started", "module_executed", "report_generated"
    request_id TEXT,
    target TEXT,
    module_name TEXT,
    details TEXT,                      -- JSON string with additional info
    system_user TEXT                   -- OS username
);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_request ON audit_log(request_id);
```

---

## 3. File Storage Structure

```
data/requests/{request_id}/
│
├── metadata.json                   # Scan metadata
│   {
│       "request_id": "req_20260120_143052_abc123",
│       "target": "John Doe",
│       "target_type": "person",
│       "target_inputs": {
│           "name": "John Doe",
│           "email": "john@example.com",
│           "username": "johndoe"
│       },
│       "status": "completed",
│       "started_at": "2026-01-20T14:30:52Z",
│       "completed_at": "2026-01-20T14:45:23Z",
│       "modules_executed": ["email_validator", "hibp", "sherlock", ...],
│       "modules_failed": ["linkedin_scraper"],
│       "modules_skipped": ["dehashed"],
│       "total_findings": 127,
│       "risk_score": 8.5,
│       "risk_level": "high",
│       "execution_time_seconds": 871,
│       "version": "1.0.0"
│   }
│
├── raw_data/                       # One JSON file per module
│   ├── email_validator.json
│   ├── hibp_breach_check.json
│   ├── sherlock_username.json
│   ├── github_api.json
│   ├── reddit_api.json
│   ├── google_cse.json
│   ├── linkedin_scraper.json
│   ├── instagram_scraper.json
│   ├── dns_recon.json
│   ├── whois_lookup.json
│   ├── ip_lookup.json
│   ├── face_recognition.json
│   └── exif_extractor.json
│
├── images/                         # Downloaded images (deduped by hash)
│   ├── profile_github.jpg
│   ├── profile_linkedin.jpg
│   ├── profile_instagram.jpg
│   ├── post_ig_001.jpg
│   ├── post_ig_002.jpg
│   └── exif_metadata.json         # Extracted EXIF for all images
│
├── screenshots/                    # Playwright screenshots
│   ├── linkedin_profile.png
│   ├── instagram_feed.png
│   ├── facebook_about.png
│   └── google_results.png
│
├── correlation/                    # AI analysis outputs
│   ├── entity_map.json            # All discovered entities cross-referenced
│   ├── connections.json           # Discovered connections between entities
│   ├── timeline.json              # Chronological events
│   ├── risk_assessment.json       # Detailed risk breakdown
│   └── anomalies.json            # Inconsistencies found
│
└── reports/                        # Final exports
    ├── executive_summary.md
    ├── full_report.md
    ├── full_report.html
    ├── full_report.pdf
    ├── technical_data.json        # Machine-readable structured output
    └── export.csv                 # Spreadsheet-friendly export
```

---

## 4. Pydantic Models (`app/database/models.py`)

```python
"""
Pydantic models for all data entities.
Used for validation, serialization, and API responses.
"""
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Any

class ScanMetadata(BaseModel):
    request_id: str
    target: str
    target_type: str
    target_inputs: dict[str, str]
    status: str = "pending"
    started_at: datetime
    completed_at: datetime | None = None
    modules_executed: list[str] = []
    modules_failed: list[str] = []
    modules_skipped: list[str] = []
    total_findings: int = 0
    risk_score: float | None = None
    risk_level: str | None = None
    execution_time_seconds: int = 0
    version: str = "1.0.0"

class PersonEntity(BaseModel):
    name: str
    aliases: list[str] = []
    emails: list[str] = []
    usernames: list[str] = []
    phones: list[str] = []
    locations: list[str] = []
    employers: list[str] = []
    education: list[str] = []

class BreachRecord(BaseModel):
    source: str
    name: str
    breach_date: str | None = None
    data_classes: list[str] = []
    is_verified: bool = False
    pwn_count: int | None = None

class SocialProfile(BaseModel):
    platform: str
    username: str
    profile_url: str
    display_name: str | None = None
    bio: str | None = None
    follower_count: int | None = None
    following_count: int | None = None
    post_count: int | None = None
    created_at: str | None = None
    is_verified: bool = False
    profile_image_path: str | None = None

class RiskAssessment(BaseModel):
    score: float = Field(ge=0, le=10)
    level: str  # low, medium, high, critical
    breakdown: dict[str, float] = {}
    top_risks: list[str] = []
    recommendations: list[str] = []
```
