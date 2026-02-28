"""
Custom exception hierarchy for GOD_EYE.

Use these exceptions throughout the codebase for consistent error handling.
The orchestrator catches these and decides whether to retry or skip a module.

Hierarchy:
    GodEyeError
    ├── ModuleError
    ├── APIError
    │   ├── RateLimitError
    │   └── AuthenticationError
    ├── BrowserError
    │   └── CaptchaError
    ├── ValidationError
    ├── CacheError
    ├── DatabaseError
    └── ConfigurationError
"""


class GodEyeError(Exception):
    """Base exception for all GOD_EYE errors."""


# ── Module Errors ─────────────────────────────────────────────────

class ModuleError(GodEyeError):
    """A module failed during execution. Non-fatal — scan continues."""

    def __init__(self, module_name: str, message: str) -> None:
        self.module_name = module_name
        super().__init__(f"[{module_name}] {message}")


# ── API Errors ────────────────────────────────────────────────────

class APIError(GodEyeError):
    """An external API returned an unexpected error response."""

    def __init__(self, api_name: str, status_code: int, message: str) -> None:
        self.api_name = api_name
        self.status_code = status_code
        super().__init__(f"[{api_name}] HTTP {status_code}: {message}")


class RateLimitError(APIError):
    """
    Rate limit exceeded (HTTP 429).

    This error triggers exponential backoff and retry logic in tenacity.
    The `retry_after` attribute specifies how many seconds to wait.
    """

    def __init__(self, api_name: str, retry_after: int | None = None) -> None:
        self.retry_after = retry_after or 60
        super().__init__(api_name, 429, f"Rate limited. Retry after: {self.retry_after}s")


class AuthenticationError(APIError):
    """
    Authentication failed (bad API key, expired token, wrong credentials).

    This is a permanent failure — do NOT retry. Skip the module.
    """

    def __init__(self, api_name: str, message: str = "Authentication failed") -> None:
        self.api_name = api_name
        GodEyeError.__init__(self, f"[{api_name}] Auth error: {message}")
        self.status_code = 401


# ── Browser Errors ────────────────────────────────────────────────

class BrowserError(GodEyeError):
    """
    Browser automation failed.

    Could be: page load timeout, element not found, navigation error.
    May be retryable depending on context.
    """

    def __init__(self, module_name: str, message: str, url: str | None = None) -> None:
        self.module_name = module_name
        self.url = url
        super().__init__(f"[{module_name}] Browser error{f' on {url}' if url else ''}: {message}")


class CaptchaError(BrowserError):
    """
    CAPTCHA was detected and could not be solved.

    Non-retryable — log warning and skip the module.
    """

    def __init__(self, module_name: str, url: str | None = None) -> None:
        super().__init__(module_name, "CAPTCHA detected — cannot proceed without solving", url)


class LoginError(BrowserError):
    """Browser-based login failed (wrong credentials or platform blocked)."""

    def __init__(self, module_name: str, platform: str) -> None:
        super().__init__(module_name, f"Login failed for {platform}")


# ── Data Errors ───────────────────────────────────────────────────

class ValidationError(GodEyeError):
    """
    Input validation failed.

    Raised when target format is invalid for the requested module.
    """

    def __init__(self, field: str, value: str, reason: str) -> None:
        self.field = field
        self.value = value
        super().__init__(f"Validation failed for {field}='{value}': {reason}")


class CacheError(GodEyeError):
    """
    Cache read/write failed.

    Non-fatal — the module should continue without cache.
    """


class DatabaseError(GodEyeError):
    """Neo4j or Redis database operation failed."""

    def __init__(self, db: str, operation: str, message: str) -> None:
        self.db = db
        self.operation = operation
        super().__init__(f"[{db}] {operation} failed: {message}")


# ── Configuration Errors ──────────────────────────────────────────

class ConfigurationError(GodEyeError):
    """
    Invalid or missing configuration.

    Raised at startup when required configuration is missing or invalid.
    """

    def __init__(self, setting: str, message: str) -> None:
        self.setting = setting
        super().__init__(f"Configuration error for '{setting}': {message}")


class MissingAPIKeyError(ConfigurationError):
    """
    A required API key is not configured.

    Note: Most modules treat missing keys as a SKIP (not an error).
    Only raise this if the key is truly mandatory for the operation.
    """

    def __init__(self, api_name: str, env_var: str) -> None:
        self.api_name = api_name
        self.env_var = env_var
        super().__init__(
            env_var,
            f"{api_name} API key not configured. Set {env_var} in .env"
        )
