"""
GOD_EYE intelligence modules package.

The module registry maps module name strings to their class types.
The orchestrator imports get_registry() at runtime (lazy, to avoid circular
imports) and selects which modules to run based on target type, phase, and
API key availability.

Auto-discovery: walks all .py files in app/modules/ recursively, imports them,
finds all classes that subclass BaseModule, and registers them.

Usage:
    from app.modules import get_registry, list_modules, get_modules_for_target
    registry = get_registry()
    modules = get_modules_for_target(TargetType.EMAIL)
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)

# Registry mapping: module_name -> module class
_registry: dict[str, Any] | None = None


def get_registry() -> dict[str, Any]:
    """
    Return the module registry, building it lazily on first call via auto-discovery.

    Returns:
        Dict mapping module name -> module class.
    """
    global _registry
    if _registry is None:
        _registry = _discover_modules()
    return _registry


def _discover_modules() -> dict[str, Any]:
    """
    Walk app/modules/ recursively and discover all BaseModule subclasses.

    Imports every .py file found under app/modules/, inspects each for
    non-abstract BaseModule subclasses, instantiates them to read metadata,
    and registers them by their metadata name.

    Returns:
        Dict mapping module name -> module class.
    """
    from app.modules.base import BaseModule

    registry: dict[str, Any] = {}
    seen_classes: set[type[Any]] = set()
    modules_dir = Path(__file__).parent

    for finder, name, ispkg in pkgutil.walk_packages(
        path=[str(modules_dir)],
        prefix="app.modules.",
        onerror=lambda x: None,
    ):
        # Skip the base and __init__ themselves
        if name in ("app.modules.base", "app.modules"):
            continue

        try:
            module = importlib.import_module(name)
            for attr_name in dir(module):
                obj = getattr(module, attr_name)
                if (
                    inspect.isclass(obj)
                    and issubclass(obj, BaseModule)
                    and obj is not BaseModule
                    and not inspect.isabstract(obj)
                    and obj not in seen_classes
                ):
                    seen_classes.add(obj)
                    instance = obj()
                    meta = instance.metadata()
                    registry[meta.name] = obj
                    logger.debug("module_registered", name=meta.name, source=name)
        except Exception as exc:
            logger.warning("module_discovery_failed", module=name, error=str(exc))

    logger.info("modules_discovered", count=len(registry))
    return registry


def list_modules() -> list[dict[str, Any]]:
    """
    List all registered modules with their metadata.

    Returns:
        Sorted list of dicts with module metadata fields.
    """
    registry = get_registry()
    result: list[dict[str, Any]] = []
    for name, cls in registry.items():
        try:
            meta = cls().metadata()
            result.append(
                {
                    "name": meta.name,
                    "display_name": meta.display_name,
                    "description": meta.description,
                    "phase": meta.phase.value,
                    "requires_auth": meta.requires_auth,
                    "requires_browser": meta.requires_browser,
                    "requires_proxy": meta.requires_proxy,
                    "enabled_by_default": meta.enabled_by_default,
                    "supported_targets": [t.value for t in meta.supported_targets],
                    "tags": meta.tags,
                }
            )
        except Exception as exc:
            logger.warning("module_list_failed", name=name, error=str(exc))
    return sorted(result, key=lambda x: (x["phase"], x["name"]))


def get_modules_for_target(target_type: Any) -> list[str]:
    """
    Get all module names that support a given target type.

    Args:
        target_type: A TargetType enum value.

    Returns:
        List of module name strings.
    """
    registry = get_registry()
    result: list[str] = []
    for name, cls in registry.items():
        try:
            meta = cls().metadata()
            if target_type in meta.supported_targets:
                result.append(name)
        except Exception as exc:
            logger.warning("module_target_filter_failed", name=name, error=str(exc))
    return result
