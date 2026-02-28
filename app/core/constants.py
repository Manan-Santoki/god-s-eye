"""
Enums and constants used throughout GOD_EYE.

All enums use str base class for easy JSON serialization.
"""

from enum import Enum, StrEnum


class TargetType(StrEnum):
    """Type of intelligence target being investigated."""

    PERSON = "person"
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    DOMAIN = "domain"
    IP = "ip"
    COMPANY = "company"


class ScanStatus(StrEnum):
    """Lifecycle status of a scan."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RiskLevel(StrEnum):
    """Privacy risk level derived from risk score."""

    LOW = "low"  # Score 1.0 – 3.0
    MEDIUM = "medium"  # Score 3.1 – 6.0
    HIGH = "high"  # Score 6.1 – 8.0
    CRITICAL = "critical"  # Score 8.1 – 10.0


class ModulePhase(int, Enum):
    """
    Execution phase for each intelligence module.

    Phases run sequentially. Modules within a phase run in parallel.
    """

    FAST_API = 1  # No auth; quick API calls; local computations
    BREACH_DB = 2  # Breach database lookups (HIBP, DeHashed, IntelX)
    SEARCH_ENGINE = 3  # Web search queries (Google, Bing, DuckDuckGo)
    BROWSER_AUTH = 4  # Browser automation with login (LinkedIn, Instagram)
    IMAGE_PROCESSING = 5  # Image download, EXIF extraction, face recognition
    DEEP_ANALYSIS = 6  # Infrastructure recon (Shodan, Censys, subdomains)
    AI_CORRELATION = 7  # AI-powered cross-reference and analysis
    REPORT_GEN = 8  # Final report generation in all formats


class ExportFormat(StrEnum):
    """Supported export formats for scan results."""

    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"
    CSV = "csv"
    GRAPH = "neo4j"


class Platform(StrEnum):
    """Known social / professional platforms."""

    GITHUB = "github"
    REDDIT = "reddit"
    TWITTER = "twitter"
    LINKEDIN = "linkedin"
    INSTAGRAM = "instagram"
    FACEBOOK = "facebook"
    TIKTOK = "tiktok"
    YOUTUBE = "youtube"
    MEDIUM = "medium"
    UNKNOWN = "unknown"


# ── Disposable Email Domain list (sample — full list loaded from file) ──
DISPOSABLE_EMAIL_DOMAINS_SAMPLE = {
    "mailinator.com",
    "guerrillamail.com",
    "tempmail.com",
    "throwaway.email",
    "yopmail.com",
    "trashmail.com",
    "maildrop.cc",
    "dispostable.com",
    "fakeinbox.com",
    "sharklasers.com",
    "guerrillamailblock.com",
    "tempinbox.com",
    "10minutemail.com",
    "getairmail.com",
}

# ── Common subdomain prefixes for brute-force enumeration ──
COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "ftp",
    "smtp",
    "pop",
    "pop3",
    "imap",
    "webmail",
    "email",
    "mx",
    "mx1",
    "mx2",
    "api",
    "api2",
    "rest",
    "graphql",
    "grpc",
    "dev",
    "staging",
    "stage",
    "test",
    "qa",
    "uat",
    "demo",
    "sandbox",
    "beta",
    "alpha",
    "preview",
    "admin",
    "panel",
    "dashboard",
    "portal",
    "cp",
    "app",
    "apps",
    "mobile",
    "m",
    "blog",
    "shop",
    "store",
    "cdn",
    "static",
    "assets",
    "help",
    "support",
    "docs",
    "wiki",
    "git",
    "gitlab",
    "github",
    "svn",
    "vpn",
    "remote",
    "ssh",
    "rdp",
    "monitor",
    "status",
    "health",
    "metrics",
    "db",
    "database",
    "mysql",
    "postgres",
    "redis",
    "mongo",
    "s3",
    "files",
    "upload",
    "download",
    "auth",
    "login",
    "sso",
    "oauth",
    "ws",
    "websocket",
    "chat",
    "stream",
    "old",
    "new",
    "v2",
    "v3",
    "internal",
    "intranet",
    "corp",
    "office",
    "ns",
    "ns1",
    "ns2",
    "dns",
    "dns1",
    "dns2",
    "img",
    "images",
    "media",
    "video",
    "audio",
    "news",
    "events",
    "forum",
    "community",
    "secure",
    "ssl",
    "https",
    "data",
    "analytics",
    "track",
    "pixel",
]

# ── Common Google Dork templates ──
DORK_TEMPLATES = [
    '"{target}" site:linkedin.com',
    '"{target}" site:github.com',
    '"{target}" site:twitter.com',
    '"{target}" site:facebook.com',
    '"{target}" site:instagram.com',
    '"{target}" site:pastebin.com',
    '"{target}" filetype:pdf',
    '"{target}" inurl:resume OR inurl:cv OR inurl:portfolio',
    '"{target}" intext:password OR intext:credentials',
    'intitle:"{target}"',
    '"{target}" site:slideshare.net',
    '"{target}" site:medium.com',
    '"{target}" site:reddit.com',
]

# ── Risk scoring weights ──
RISK_WEIGHTS = {
    "email_breach_each": 2.0,  # Per breach (max 4)
    "passwords_exposed": 3.0,  # Found plaintext/hash passwords
    "social_platforms_per_5": 1.0,  # Per 5 public platforms (max 3)
    "personal_info_each": 1.0,  # Public phone/address/employer
    "face_match_unexpected": 2.0,  # Face found on unexpected platform
    "exif_gps_data": 2.0,  # GPS coords in public images
    "whois_not_private": 1.0,  # Domain with public registrant info
    "secret_in_code": 3.0,  # API key/password in public repo
    "public_social_per": 0.5,  # Per public social profile
}
