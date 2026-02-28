"""
Base module interface for all GOD_EYE intelligence modules.

Every module must subclass BaseModule and implement the run() method.
The orchestrator discovers modules via the registry, validates metadata,
checks API key availability, and calls run() concurrently within each phase.

Every module provides:
- metadata(): returns ModuleMetadata describing the module
- run(): executes the intelligence gathering, returns ModuleResult
- cleanup(): optional cleanup (close connections, etc.)
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from app.core.constants import ModulePhase, TargetType
from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ModuleMetadata:
    """
    Static metadata describing a module's identity, requirements, and phase.

    Returned by BaseModule.metadata() and used by the orchestrator for
    scheduling, filtering, and display.
    """

    name: str
    """Unique snake_case module identifier (e.g. 'github_api')."""

    display_name: str
    """Human-readable name shown in the UI (e.g. 'GitHub OSINT')."""

    description: str
    """One-line description of what this module does."""

    phase: ModulePhase
    """Execution phase — determines when this module runs."""

    supported_targets: list[TargetType]
    """Target types this module can process."""

    requires_auth: bool = False
    """
    Whether this module requires an API key.

    If True, the orchestrator checks for a key before including it in the scan.
    """

    requires_proxy: bool = False
    """Whether this module should use proxy rotation for requests."""

    requires_browser: bool = False
    """Whether this module needs Playwright browser automation."""

    rate_limit_rpm: int = 60
    """Maximum requests per minute for this module."""

    timeout_seconds: int = 30
    """Per-request timeout in seconds."""

    priority: int = 1
    """Execution priority within its phase (1=highest, 10=lowest)."""

    enabled_by_default: bool = True
    """Whether this module is enabled if not explicitly configured."""

    author: str = "GOD_EYE"
    """Module author for attribution."""

    version: str = "1.0.0"
    """Semantic version for the module."""

    tags: list[str] = field(default_factory=list)
    """Searchable tags for module categorisation (e.g. ['email', 'breach'])."""


@dataclass
class ModuleResult:
    """
    Standardised return value from BaseModule.run().

    The orchestrator inspects success to decide whether to update the session
    context, and merges data into the phase results dict.
    """

    success: bool
    """True if the module completed without fatal errors."""

    data: dict[str, Any] = field(default_factory=dict)
    """Structured output data. Schema is module-specific."""

    errors: list[str] = field(default_factory=list)
    """Human-readable error messages accumulated during execution."""

    warnings: list[str] = field(default_factory=list)
    """Non-fatal warnings (e.g., partial data, rate-limited fallback)."""

    raw_responses: dict[str, Any] = field(default_factory=dict)
    """Optional raw API responses for debugging / audit trail."""

    @classmethod
    def ok(cls, data: dict[str, Any], warnings: list[str] | None = None) -> "ModuleResult":
        """Construct a successful result."""
        return cls(success=True, data=data, warnings=warnings or [])

    @classmethod
    def fail(cls, *errors: str) -> "ModuleResult":
        """Construct a failed result."""
        return cls(success=False, errors=list(errors))

    def add_error(self, message: str) -> None:
        """Append an error message."""
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        """Append a warning message."""
        self.warnings.append(message)


class BaseModule(abc.ABC):
    """
    Abstract base class for all GOD_EYE intelligence modules.

    Subclasses must implement:
        - metadata() -> ModuleMetadata
        - run(target, target_type, context) -> ModuleResult

    All I/O operations must be async. Use aiohttp.ClientSession for HTTP.
    Use tenacity @retry decorators on individual API call methods.
    """

    @abc.abstractmethod
    def metadata(self) -> ModuleMetadata:
        """Return static metadata describing this module."""
        ...

    @abc.abstractmethod
    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        """
        Execute the module against a target.

        Args:
            target: The primary target string (email, username, domain, IP, etc.).
            target_type: The TargetType enum value for the target.
            context: Shared scan context including previously discovered entities
                     and results from earlier phases.

        Returns:
            ModuleResult with structured data or error information.
        """
        ...

    async def cleanup(self) -> None:
        """Optional: clean up resources after run() completes."""
        pass

    def _get_secret(self, secret_str: Any) -> str | None:
        """
        Safely extract a plain string from a pydantic SecretStr or None.

        Args:
            secret_str: A SecretStr instance or None.

        Returns:
            Plain string value or None.
        """
        if secret_str is None:
            return None
        if hasattr(secret_str, "get_secret_value"):
            return secret_str.get_secret_value() or None
        return str(secret_str) or None
