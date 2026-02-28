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
import inspect
from typing import Any

from app.core.constants import ModulePhase, TargetType
from app.core.logging import get_logger

logger = get_logger(__name__)


class ModuleMetadata:
    """
    Static metadata describing a module's identity, requirements, and phase.

    Returned by BaseModule.metadata() and used by the orchestrator for
    scheduling, filtering, and display.
    """

    def __init__(
        self,
        *,
        name: str,
        display_name: str,
        description: str,
        phase: ModulePhase | int,
        supported_targets: list[TargetType | str] | None = None,
        target_types: list[TargetType | str] | None = None,
        requires_auth: bool | None = None,
        requires_api_key: bool | None = None,
        requires_proxy: bool = False,
        requires_browser: bool = False,
        rate_limit_rpm: int | None = None,
        rate_limit_per_minute: int | None = None,
        timeout_seconds: int = 30,
        priority: int = 1,
        enabled_by_default: bool = True,
        author: str = "GOD_EYE",
        version: str = "1.0.0",
        tags: list[str] | None = None,
    ) -> None:
        self.name = name
        self.display_name = display_name
        self.description = description
        self.phase = phase if isinstance(phase, ModulePhase) else ModulePhase(phase)
        raw_targets = supported_targets if supported_targets is not None else target_types or []
        self.supported_targets = [
            target if isinstance(target, TargetType) else TargetType(target)
            for target in raw_targets
        ]
        self.requires_auth = (
            requires_auth if requires_auth is not None else bool(requires_api_key)
        )
        self.requires_proxy = requires_proxy
        self.requires_browser = requires_browser
        self.rate_limit_rpm = (
            rate_limit_rpm if rate_limit_rpm is not None else rate_limit_per_minute or 60
        )
        self.timeout_seconds = timeout_seconds
        self.priority = priority
        self.enabled_by_default = enabled_by_default
        self.author = author
        self.version = version
        self.tags = list(tags or [])

    @property
    def target_types(self) -> list[TargetType]:
        """Backward-compatible alias for legacy modules/tests."""
        return self.supported_targets

    @target_types.setter
    def target_types(self, value: list[TargetType | str]) -> None:
        self.supported_targets = [
            target if isinstance(target, TargetType) else TargetType(target)
            for target in value
        ]

    @property
    def requires_api_key(self) -> bool:
        """Backward-compatible alias for legacy modules/tests."""
        return self.requires_auth

    @requires_api_key.setter
    def requires_api_key(self, value: bool) -> None:
        self.requires_auth = value

    @property
    def rate_limit_per_minute(self) -> int:
        """Backward-compatible alias for legacy modules/tests."""
        return self.rate_limit_rpm

    @rate_limit_per_minute.setter
    def rate_limit_per_minute(self, value: int) -> None:
        self.rate_limit_rpm = value


class ModuleResult:
    """
    Standardised return value from BaseModule.run().

    The orchestrator inspects success to decide whether to update the session
    context, and merges data into the phase results dict.
    """

    def __init__(
        self,
        *,
        success: bool,
        data: dict[str, Any] | None = None,
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
        raw_responses: dict[str, Any] | None = None,
        module_name: str = "",
        target: str = "",
        execution_time_ms: int = 0,
        findings_count: int | None = None,
        error: str | None = None,
    ) -> None:
        self.module_name = module_name
        self.target = target
        self.success = success
        self.data = data or {}
        self.errors = list(errors or [])
        if error:
            self.errors.append(error)
        self.warnings = list(warnings or [])
        self.raw_responses = raw_responses or {}
        self.execution_time_ms = execution_time_ms
        self.findings_count = (
            findings_count
            if findings_count is not None
            else self._infer_findings_count(self.data)
        )

    @classmethod
    def ok(
        cls,
        data: dict[str, Any],
        warnings: list[str] | None = None,
        **kwargs: Any,
    ) -> "ModuleResult":
        """Construct a successful result."""
        return cls(success=True, data=data, warnings=warnings or [], **kwargs)

    @classmethod
    def fail(cls, *errors: str, **kwargs: Any) -> "ModuleResult":
        """Construct a failed result."""
        return cls(success=False, errors=list(errors), **kwargs)

    def add_error(self, message: str) -> None:
        """Append an error message."""
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        """Append a warning message."""
        self.warnings.append(message)

    @property
    def error(self) -> str | None:
        """Backward-compatible accessor for the first error."""
        return self.errors[0] if self.errors else None

    @error.setter
    def error(self, value: str | None) -> None:
        self.errors = [value] if value else []

    @staticmethod
    def _infer_findings_count(data: Any) -> int:
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict):
            for key in (
                "findings_count",
                "total_found",
                "profile_count",
                "sites_found",
                "total_breaches",
                "breach_count",
            ):
                value = data.get(key)
                if isinstance(value, int):
                    return value
            return len([value for value in data.values() if value not in (None, [], {}, "")])
        return int(bool(data))


class BaseModule(abc.ABC):
    """
    Abstract base class for all GOD_EYE intelligence modules.

    Subclasses must implement:
        - metadata() -> ModuleMetadata
        - run(target, target_type, context) -> ModuleResult

    All I/O operations must be async. Use aiohttp.ClientSession for HTTP.
    Use tenacity @retry decorators on individual API call methods.
    """

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Wrap subclass run() methods so legacy call sites keep working."""
        super().__init_subclass__(**kwargs)
        def build_context(
            target: str,
            target_type: TargetType,
            context: Any,
            target_inputs: Any,
        ) -> dict[str, Any]:
            if context is None and target_inputs is not None:
                context = {"target_inputs": target_inputs}
            elif context is not None and target_inputs is not None:
                context = dict(context)
                context.setdefault("target_inputs", target_inputs)

            if context is None:
                context = {}
            else:
                context = dict(context)

            if target_inputs:
                context.setdefault("target_inputs", dict(target_inputs))
                for key, value in target_inputs.items():
                    context.setdefault(key, value)
                if "domain" in target_inputs:
                    context.setdefault("target_domain", target_inputs["domain"])
                if "name" in target_inputs:
                    context.setdefault("person_name", target_inputs["name"])
                    context.setdefault("discovered_names", [target_inputs["name"]])

            if target_type == TargetType.PERSON:
                context.setdefault("person_name", target)
                context.setdefault("discovered_names", [target])

            return context

        run_method = cls.__dict__.get("run")
        if run_method is not None and not getattr(run_method, "_god_eye_wrapped", False):
            run_signature = inspect.signature(run_method)

            async def wrapped_run(self, target: str, target_type: TargetType, *args: Any, **kwargs: Any) -> ModuleResult:
                context = build_context(
                    target=target,
                    target_type=target_type,
                    context=kwargs.pop("context", None),
                    target_inputs=kwargs.pop("target_inputs", None),
                )

                if "context" in run_signature.parameters and len(args) == 0 and "context" not in kwargs:
                    kwargs["context"] = context

                result = await run_method(self, target, target_type, *args, **kwargs)
                if isinstance(result, ModuleResult):
                    meta = self.metadata()
                    if not result.module_name:
                        result.module_name = meta.name
                    if not result.target:
                        result.target = target
                    if result.findings_count == 0 and result.success:
                        result.findings_count = ModuleResult._infer_findings_count(result.data)
                return result

            wrapped_run._god_eye_wrapped = True  # type: ignore[attr-defined]
            setattr(cls, "run", wrapped_run)

        validate_method = cls.__dict__.get("validate")
        if validate_method is not None and not getattr(validate_method, "_god_eye_wrapped", False):
            validate_signature = inspect.signature(validate_method)

            async def wrapped_validate(
                self,
                target: str,
                target_type: TargetType,
                *args: Any,
                **kwargs: Any,
            ) -> bool:
                context = build_context(
                    target=target,
                    target_type=target_type,
                    context=kwargs.pop("context", None),
                    target_inputs=kwargs.pop("target_inputs", None),
                )

                if "context" in validate_signature.parameters and len(args) == 0 and "context" not in kwargs:
                    kwargs["context"] = context

                return await validate_method(self, target, target_type, *args, **kwargs)

            wrapped_validate._god_eye_wrapped = True  # type: ignore[attr-defined]
            setattr(cls, "validate", wrapped_validate)

    @abc.abstractmethod
    def metadata(self) -> ModuleMetadata:
        """Return static metadata describing this module."""
        ...

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
        raise NotImplementedError

    async def cleanup(self) -> None:
        """Optional: clean up resources after run() completes."""
        pass

    async def validate(self, target: str, target_type: TargetType, **kwargs: Any) -> bool:
        """Default validation hook for legacy modules/tests."""
        if target_type not in self.metadata().supported_targets:
            return False

        from app.utils.validators import (
            is_valid_domain,
            is_valid_email,
            is_valid_ip,
            is_valid_phone,
            is_valid_username,
        )

        target = target.strip()
        if target_type == TargetType.EMAIL:
            return is_valid_email(target)
        if target_type == TargetType.DOMAIN:
            return is_valid_domain(target)
        if target_type == TargetType.IP:
            return is_valid_ip(target)
        if target_type == TargetType.PHONE:
            return is_valid_phone(target)
        if target_type == TargetType.USERNAME:
            return len(target) >= 2 and is_valid_username(target)
        if target_type == TargetType.PERSON:
            parts = [part for part in target.split() if part]
            return len("".join(parts)) >= 2 and len(parts) >= 2
        if target_type == TargetType.COMPANY:
            return len(target) >= 2
        return bool(target)

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
