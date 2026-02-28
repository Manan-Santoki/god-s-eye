"""
Structured logging setup using structlog.

Usage:
    from app.core.logging import get_logger
    logger = get_logger(__name__)
    logger.info("module_started", module="hibp", target="user@example.com")

Never use print() anywhere in the codebase — always use this logger.
"""

import logging
import sys
from pathlib import Path
from typing import Any

import structlog
from structlog.types import EventDict, WrappedLogger


def _add_caller_info(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Add module name from logger name to every log event."""
    if hasattr(logger, "name"):
        event_dict.setdefault("logger", logger.name)
    return event_dict


def setup_logging(
    log_level: str = "INFO",
    log_format: str = "text",
    log_dir: Path | None = None,
) -> None:
    """
    Configure structured logging for the entire application.

    Must be called once at application startup (in cli.py or main.py).

    Args:
        log_level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_format: Output format. "json" for production, "text" for development.
        log_dir: Optional directory to write log files. If None, only stdout.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Standard library logging config (for third-party libraries)
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )

    # Silence noisy libraries
    for noisy_lib in ["httpx", "httpcore", "playwright", "neo4j", "aiohttp"]:
        logging.getLogger(noisy_lib).setLevel(logging.WARNING)

    # Shared processors applied to every log event
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.ExceptionRenderer(),
        _add_caller_info,
    ]

    if log_format == "json":
        # JSON output for production / log aggregation (Datadog, CloudWatch, etc.)
        renderer = structlog.processors.JSONRenderer()
    else:
        # Human-readable colored output for development
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.reset_defaults()
    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Set up file logging if requested
    if log_dir:
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_dir / "app.log")
        file_handler.setLevel(level)
        logging.getLogger().addHandler(file_handler)

        # Separate audit log (append-only, never rotate)
        audit_handler = logging.FileHandler(log_dir / "audit.log")
        audit_handler.setLevel(logging.INFO)
        logging.getLogger("god_eye.audit").addHandler(audit_handler)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """
    Get a structlog logger bound with the given name.

    Args:
        name: Logger name, typically __name__ of the calling module.

    Returns:
        A bound structlog logger with all configured processors.

    Example:
        logger = get_logger(__name__)
        logger.info("scan_started", target="john@example.com", phase=1)
        logger.error("api_failed", api="hibp", status=429, retry_after=60)
    """
    return structlog.stdlib.get_logger(name)


def get_audit_logger() -> structlog.stdlib.BoundLogger:
    """
    Get the audit logger for recording who searched what.

    All searches must be logged here for compliance/ethics requirements.
    This log is append-only and should never be cleared.
    """
    return structlog.stdlib.get_logger("god_eye.audit")
