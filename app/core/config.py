"""
Centralized configuration management.

Loads settings from:
1. .env file (secrets, API keys, infrastructure URIs)
2. config.yaml (module-level enable/disable, fine-grained settings)

Usage:
    from app.core.config import settings, module_config
    print(settings.neo4j_uri)
    print(module_config.get("modules", {}).get("email", {}).get("validator", {}).get("enabled"))
"""

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables and .env file.

    All API keys are optional — modules check availability at runtime and
    gracefully skip themselves if their key is not configured.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # Ignore extra env vars (don't raise errors)
    )

    # ── Application ────────────────────────────────────────────
    app_env: str = "development"
    log_level: str = "INFO"
    log_format: str = "text"
    api_port: int = 8000
    data_dir: Path = Path("./data")
    data_retention_days: int = 90
    max_concurrent_modules: int = 10
    max_concurrent_browsers: int = 3
    request_timeout_seconds: int = 30
    respect_robots_txt: bool = True
    audit_log_enabled: bool = True
    consent_required: bool = True

    # ── Infrastructure ────────────────────────────────────────
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: SecretStr = SecretStr("god_eye_password")
    redis_url: str = "redis://localhost:6379"

    # ── VPN / Gluetun ─────────────────────────────────────────
    vpn_enabled: bool = False
    vpn_provider: str = "nordvpn"
    vpn_type: str = "wireguard"
    gluetun_http_proxy: str = "http://gluetun:8888"  # Internal docker proxy

    # ── Email Intelligence ────────────────────────────────────
    hibp_api_key: SecretStr | None = None
    hunter_io_api_key: SecretStr | None = None
    dehashed_email: str | None = None
    dehashed_api_key: SecretStr | None = None
    emailrep_api_key: SecretStr | None = None
    intelx_api_key: SecretStr | None = None

    # ── Search Engines ────────────────────────────────────────
    serpapi_api_key: SecretStr | None = None
    serpapi_key: SecretStr | None = None
    serp_api_key: SecretStr | None = None
    serpapi_base_url: str = "https://serpapi.com/search.json"
    serpapi_location: str | None = None
    bing_api_key: SecretStr | None = None
    shodan_api_key: SecretStr | None = None
    virustotal_api_key: SecretStr | None = None
    crawl4ai_base_url: str | None = None
    crawl4ai_bearer_token: SecretStr | None = None
    crawl4ai_timeout_seconds: int = 90

    # ── Social Media ──────────────────────────────────────────
    github_token: SecretStr | None = None
    twitter_bearer_token: SecretStr | None = None
    reddit_client_id: str | None = None
    reddit_client_secret: SecretStr | None = None
    reddit_user_agent: str = "GOD_EYE/1.0 by researcher"
    youtube_api_key: SecretStr | None = None

    # ── Domain & Network ──────────────────────────────────────
    whoisxml_api_key: SecretStr | None = None
    securitytrails_api_key: SecretStr | None = None
    ipinfo_token: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    censys_api_id: str | None = None
    censys_api_secret: SecretStr | None = None

    # ── Phone ─────────────────────────────────────────────────
    numverify_api_key: SecretStr | None = None
    twilio_account_sid: str | None = None
    twilio_auth_token: SecretStr | None = None

    # ── Image Intelligence ────────────────────────────────────
    tineye_api_key: SecretStr | None = None
    google_vision_api_key: SecretStr | None = None

    # ── Business ─────────────────────────────────────────────
    opencorporates_api_token: SecretStr | None = None
    clearbit_api_key: SecretStr | None = None

    # ── Browser Credentials ───────────────────────────────────
    linkedin_email: str | None = None
    linkedin_password: SecretStr | None = None
    instagram_username: str | None = None
    instagram_password: SecretStr | None = None
    facebook_email: str | None = None
    facebook_password: SecretStr | None = None
    tiktok_session_id: SecretStr | None = None

    # ── Proxy ─────────────────────────────────────────────────
    use_proxy: bool = False
    proxy_list_file: str = "proxies.txt"
    proxy_rotation_strategy: str = "round_robin"
    tor_enabled: bool = False
    tor_socks_port: int = 9050
    tor_control_port: int = 9051
    tor_password: SecretStr | None = None

    # ── AI ────────────────────────────────────────────────────
    ai_provider: str = "openrouter"
    anthropic_api_key: SecretStr | None = None
    openai_api_key: SecretStr | None = None
    openrouter_api_key: SecretStr | None = None
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_site_url: str | None = None
    openrouter_app_name: str | None = "GOD_EYE"
    openrouter_vision_model: str = "anthropic/claude-3-5-sonnet"
    openrouter_report_model: str = "anthropic/claude-3-5-sonnet"
    ollama_endpoint: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    ai_model: str = "anthropic/claude-3-5-sonnet"
    ai_max_tokens: int = 4000
    enable_ai_correlation: bool = True
    enable_ai_reports: bool = True
    enable_ai_vision: bool = True

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return v.upper()

    @field_validator("ai_provider")
    @classmethod
    def validate_ai_provider(cls, v: str) -> str:
        valid = {"anthropic", "openai", "openrouter", "ollama"}
        if v.lower() not in valid:
            raise ValueError(f"ai_provider must be one of {valid}")
        return v.lower()

    @model_validator(mode="after")
    def ensure_data_dir_exists(self) -> "Settings":
        """Create data directory structure on startup."""
        dirs = [
            self.data_dir,
            self.data_dir / "requests",
            self.data_dir / "cache",
            self.data_dir / "logs",
            self.data_dir / "sessions",
            self.data_dir / "templates",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
        return self

    @model_validator(mode="after")
    def normalize_serpapi_settings(self) -> "Settings":
        """Accept common SerpApi env aliases and normalize the base URL."""
        primary = self._clean_secret(self.serpapi_api_key)
        legacy = self._clean_secret(self.serpapi_key)
        alias = self._clean_secret(self.serp_api_key)
        resolved = primary or legacy or alias
        object.__setattr__(self, "serpapi_api_key", resolved)
        object.__setattr__(self, "serpapi_key", legacy)
        object.__setattr__(self, "serp_api_key", alias)
        object.__setattr__(
            self,
            "serpapi_base_url",
            self._clean_env_string(self.serpapi_base_url) or "https://serpapi.com/search.json",
        )
        return self

    def get_proxy_url(self) -> str | None:
        """
        Return the active proxy URL for outbound requests.

        Priority: Gluetun VPN HTTP proxy > explicit proxy config > None
        """
        if self.vpn_enabled:
            return self.gluetun_http_proxy
        if self.use_proxy:
            # Individual proxy URLs are managed by ProxyRotator
            return None
        return None

    def __getattribute__(self, name: str) -> Any:
        """Allow environment variables to override loaded settings at runtime."""
        value = super().__getattribute__(name)
        if name.startswith("_"):
            return value

        cls = super().__getattribute__("__class__")
        fields = getattr(cls, "model_fields", {})
        if name not in fields:
            return value

        raw = os.getenv(name.upper())
        if raw is None:
            return value

        if isinstance(value, SecretStr):
            return SecretStr(raw)
        if isinstance(value, bool):
            return raw.strip().lower() in {"1", "true", "yes", "on"}
        if isinstance(value, int):
            try:
                return int(raw)
            except ValueError:
                return value
        if isinstance(value, Path):
            return Path(raw)
        if isinstance(value, str):
            return raw

        annotation = fields[name].annotation
        annotation_text = str(annotation)
        if "SecretStr" in annotation_text:
            return SecretStr(raw)
        if "bool" in annotation_text:
            return raw.strip().lower() in {"1", "true", "yes", "on"}
        if "int" in annotation_text:
            try:
                return int(raw)
            except ValueError:
                return value
        if "Path" in annotation_text:
            return Path(raw)
        return raw

    @staticmethod
    def _clean_env_string(value: str | None) -> str | None:
        """Normalize string settings loaded from .env placeholders."""
        if value is None:
            return None
        cleaned = value.split("#", 1)[0].strip().strip('"').strip("'")
        return cleaned or None

    @classmethod
    def _clean_secret(cls, value: SecretStr | None) -> SecretStr | None:
        """Normalize secret settings loaded from .env placeholders."""
        if value is None:
            return None
        cleaned = cls._clean_env_string(value.get_secret_value())
        return SecretStr(cleaned) if cleaned else None

    def has_api_key(self, key_name: str) -> bool:
        """Check if a given API key is configured (not None/empty)."""
        value = getattr(self, key_name, None)
        if value is None:
            return False
        if isinstance(value, SecretStr):
            return bool(value.get_secret_value())
        return bool(value)

    @classmethod
    def load_module_config(cls, config_path: Path | None = None) -> dict[str, Any]:
        """
        Load config.yaml for module-specific settings.

        Returns an empty dict if config.yaml does not exist.
        """
        path = config_path or Path("config.yaml")
        if path.exists():
            with open(path) as f:
                return yaml.safe_load(f) or {}
        return {}


# ── Singletons ────────────────────────────────────────────────────
settings = Settings()
module_config: dict[str, Any] = Settings.load_module_config()


def get_module_setting(
    category: str, module: str, key: str, default: Any = None
) -> Any:
    """
    Convenience accessor for nested module config.

    Example:
        enabled = get_module_setting("email", "validator", "enabled", True)
        max_posts = get_module_setting("social", "instagram", "max_posts", 50)
    """
    return (
        module_config.get("modules", {})
        .get(category, {})
        .get(module, {})
        .get(key, default)
    )
