"""
Pydantic v2 data models for all GOD_EYE entities.

These models are used for:
- API request/response validation
- Module output structure
- Database serialization
- Report generation input
"""

from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


# ── Base ──────────────────────────────────────────────────────────

class BaseEntity(BaseModel):
    """Base class for all GOD_EYE data entities."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    request_id: str | None = None


# ── Core Entities ─────────────────────────────────────────────────

class PersonEntity(BaseEntity):
    """Central person entity — all other entities link to this."""

    name: str
    aliases: list[str] = []
    age: int | None = None
    gender: str | None = None
    emails: list[str] = []
    usernames: list[str] = []
    phones: list[str] = []
    locations: list[str] = []
    employers: list[str] = []
    education: list[str] = []
    risk_score: float | None = None
    risk_level: str | None = None


class EmailEntity(BaseEntity):
    """Email address entity with reputation and breach data."""

    address: str
    domain: str = ""
    is_valid: bool = True
    is_breached: bool = False
    breach_count: int = 0
    is_disposable: bool = False
    reputation_score: float | None = None
    provider: str | None = None
    has_mx_records: bool = True
    has_spf: bool = False
    has_dmarc: bool = False


class UsernameEntity(BaseEntity):
    """Social media / platform account entity."""

    handle: str
    platform: str
    profile_url: str = ""
    display_name: str | None = None
    bio: str | None = None
    follower_count: int | None = None
    following_count: int | None = None
    post_count: int | None = None
    is_verified: bool = False
    account_created_at: str | None = None
    last_active: str | None = None
    profile_image_url: str | None = None
    profile_image_path: str | None = None
    screenshot_path: str | None = None
    raw_data: dict[str, Any] = {}


class PhoneEntity(BaseEntity):
    """Phone number entity with carrier and type information."""

    number: str                          # E.164 format: +1234567890
    country_code: str = ""
    country: str = ""
    carrier: str | None = None
    line_type: str | None = None         # mobile | landline | voip | toll_free
    is_valid: bool = True
    is_voip: bool = False


class DomainEntity(BaseEntity):
    """Domain name entity with WHOIS and DNS data."""

    name: str
    registrar: str | None = None
    registration_date: str | None = None
    expiration_date: str | None = None
    registrant_name: str | None = None
    registrant_org: str | None = None
    registrant_email: str | None = None
    nameservers: list[str] = []
    has_whois_privacy: bool = False
    tech_stack: list[str] = []
    is_active: bool = True


class IPEntity(BaseEntity):
    """IP address entity with geolocation and abuse data."""

    address: str
    version: int = 4
    isp: str | None = None
    organization: str | None = None
    asn: str | None = None
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    is_datacenter: bool = False
    abuse_score: int = 0
    open_ports: list[int] = []
    services: list[str] = []
    vulnerabilities: list[str] = []


class LocationEntity(BaseEntity):
    """Geographic location entity."""

    latitude: float | None = None
    longitude: float | None = None
    address: str | None = None
    city: str | None = None
    state: str | None = None
    country: str | None = None
    country_code: str | None = None
    postal_code: str | None = None
    source: str = "unknown"              # ip_geolocation | exif | social_profile | whois
    confidence: float = 1.0


class ImageEntity(BaseEntity):
    """Downloaded image entity with visual intelligence data."""

    file_path: str
    original_url: str = ""
    source_platform: str = ""
    hash_md5: str = ""
    hash_perceptual: str | None = None
    width: int | None = None
    height: int | None = None
    has_faces: bool = False
    face_count: int = 0
    has_exif: bool = False
    has_gps: bool = False
    captured_at: str | None = None
    camera_make: str | None = None
    camera_model: str | None = None
    gps_latitude: float | None = None
    gps_longitude: float | None = None
    gps_address: str | None = None


class BreachRecord(BaseEntity):
    """Data breach record from HIBP, DeHashed, or IntelX."""

    source: str                          # hibp | dehashed | intelx
    name: str
    domain: str | None = None
    breach_date: str | None = None
    data_classes: list[str] = []
    is_verified: bool = False
    is_sensitive: bool = False
    pwn_count: int | None = None
    description: str | None = None
    # DeHashed-specific fields
    exposed_email: str | None = None
    exposed_username: str | None = None
    exposed_password: str | None = None
    exposed_hash: str | None = None
    exposed_ip: str | None = None
    exposed_phone: str | None = None


class SocialProfile(BaseModel):
    """Simplified social profile summary for reports."""

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


class CompanyEntity(BaseEntity):
    """Business entity from OpenCorporates or Clearbit."""

    name: str
    domain: str | None = None
    industry: str | None = None
    employee_count: str | None = None
    jurisdiction: str | None = None
    registration_number: str | None = None
    status: str | None = None
    incorporated_date: str | None = None
    address: str | None = None
    officers: list[dict[str, Any]] = []


# ── Scan Metadata ─────────────────────────────────────────────────

class ScanMetadata(BaseModel):
    """Complete metadata for a scan session."""

    request_id: str
    target: str
    target_type: str
    target_inputs: dict[str, str] = {}
    status: str = "pending"
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    modules_executed: list[str] = []
    modules_failed: list[str] = []
    modules_skipped: list[str] = []
    total_findings: int = 0
    risk_score: float | None = None
    risk_level: str | None = None
    execution_time_seconds: int = 0
    version: str = "1.0.0"


# ── Risk Assessment ───────────────────────────────────────────────

class RiskAssessment(BaseModel):
    """Privacy risk assessment output from the AI risk scorer."""

    score: float = Field(ge=0.0, le=10.0)
    level: str                           # low | medium | high | critical
    breakdown: dict[str, float] = {}
    top_risks: list[str] = []
    recommendations: list[str] = []


# ── Timeline ──────────────────────────────────────────────────────

class TimelineEvent(BaseModel):
    """A single chronological event in the target's digital history."""

    timestamp: str
    event_type: str                      # account_created | breach | post | location_seen
    description: str
    platform: str | None = None
    source_module: str = ""
    data: dict[str, Any] = {}


# ── Correlation ───────────────────────────────────────────────────

class CorrelationFinding(BaseModel):
    """A discovered connection between entities from different modules."""

    connection_type: str                 # same_email | username_pattern | location_match
    entities: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    source_modules: list[str] = []
    evidence: list[str] = []
