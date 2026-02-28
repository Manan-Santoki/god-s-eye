"""
Scan session management.

A ScanSession tracks the state of a single OSINT scan from start to finish.
It generates the request_id, manages the output directory, and maintains
the shared context dict passed between module phases.
"""

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.constants import ScanStatus, TargetType
from app.core.logging import get_logger
from app.database.models import ScanMetadata

logger = get_logger(__name__)


def generate_request_id(target: str) -> str:
    """
    Generate a unique, deterministic request ID for a scan.

    Format: req_{YYYYMMDD}_{HHMMSS}_{target_hash}

    Example: req_20260120_143052_a1b2c3d4
    """
    now = datetime.now(timezone.utc)
    date_part = now.strftime("%Y%m%d")
    time_part = now.strftime("%H%M%S")
    hash_part = hashlib.md5(target.encode()).hexdigest()[:8]
    return f"req_{date_part}_{time_part}_{hash_part}"


class ScanSession:
    """
    Manages a single OSINT scan session.

    Responsibilities:
    - Generate request_id
    - Create output directory structure
    - Save/load scan metadata
    - Maintain the shared context dict
    - Track timing and status
    """

    def __init__(
        self,
        target: str,
        target_type: TargetType,
        target_inputs: dict[str, str] | None = None,
    ) -> None:
        self.target = target
        self.target_type = target_type
        self.target_inputs = target_inputs or {}
        self.request_id = generate_request_id(target)
        self.status = ScanStatus.PENDING
        self.started_at = datetime.now(timezone.utc)
        self.completed_at: datetime | None = None
        self._start_mono = time.monotonic()

        # Context dict passed between phases
        self.context: dict[str, Any] = {
            "request_id": self.request_id,
            "target": target,
            "target_type": target_type.value,
            "target_inputs": target_inputs or {},
            # Discovered entities (populated by modules)
            "discovered_emails": [],
            "discovered_usernames": [],
            "discovered_domains": [],
            "discovered_ips": [],
            "discovered_images": [],
            "discovered_names": [],
            "discovered_phones": [],
            "discovered_locations": [],
            # Module results (populated by orchestrator)
            "module_results": {},
        }

        # Output directories
        self.base_dir = Path(settings.data_dir) / "requests" / self.request_id
        self.raw_data_dir = self.base_dir / "raw_data"
        self.images_dir = self.base_dir / "images"
        self.screenshots_dir = self.base_dir / "screenshots"
        self.correlation_dir = self.base_dir / "correlation"
        self.reports_dir = self.base_dir / "reports"

        # Module tracking
        self.modules_executed: list[str] = []
        self.modules_failed: list[str] = []
        self.modules_skipped: list[str] = []
        self.total_findings: int = 0

    def setup_directories(self) -> None:
        """Create all output directories."""
        for d in [
            self.base_dir,
            self.raw_data_dir,
            self.images_dir,
            self.screenshots_dir,
            self.correlation_dir,
            self.reports_dir,
        ]:
            d.mkdir(parents=True, exist_ok=True)
        logger.info("session_dirs_created", request_id=self.request_id, path=str(self.base_dir))

    def save_metadata(self) -> None:
        """Write current scan state to metadata.json."""
        meta = self.to_metadata()
        meta_path = self.base_dir / "metadata.json"
        with open(meta_path, "w") as f:
            json.dump(meta.model_dump(mode="json"), f, indent=2, default=str)

    def to_metadata(self) -> ScanMetadata:
        """Convert current session state to ScanMetadata model."""
        elapsed = int(time.monotonic() - self._start_mono)
        return ScanMetadata(
            request_id=self.request_id,
            target=self.target,
            target_type=self.target_type.value,
            target_inputs=self.target_inputs,
            status=self.status.value,
            started_at=self.started_at,
            completed_at=self.completed_at,
            modules_executed=self.modules_executed,
            modules_failed=self.modules_failed,
            modules_skipped=self.modules_skipped,
            total_findings=self.total_findings,
            risk_score=self.context.get("risk_score"),
            risk_level=self.context.get("risk_level"),
            execution_time_seconds=elapsed,
        )

    def start(self) -> None:
        """Mark session as running."""
        self.status = ScanStatus.RUNNING
        self.setup_directories()
        self.save_metadata()
        logger.info(
            "scan_started",
            request_id=self.request_id,
            target=self.target,
            target_type=self.target_type.value,
        )

    def complete(self) -> None:
        """Mark session as completed."""
        self.status = ScanStatus.COMPLETED
        self.completed_at = datetime.now(timezone.utc)
        self.save_metadata()
        elapsed = int(time.monotonic() - self._start_mono)
        logger.info(
            "scan_completed",
            request_id=self.request_id,
            target=self.target,
            elapsed_seconds=elapsed,
            findings=self.total_findings,
        )

    def fail(self, reason: str) -> None:
        """Mark session as failed."""
        self.status = ScanStatus.FAILED
        self.completed_at = datetime.now(timezone.utc)
        self.save_metadata()
        logger.error("scan_failed", request_id=self.request_id, reason=reason)

    def save_module_result(self, module_name: str, result: dict[str, Any]) -> None:
        """Save a module's raw output to raw_data/{module_name}.json."""
        output_path = self.raw_data_dir / f"{module_name}.json"
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2, default=str)

    def add_discovered(self, entity_type: str, value: str | list[str]) -> None:
        """
        Add discovered entities to the shared context.

        These are made available to all subsequent phases.
        Automatically deduplicates entries.
        """
        key = f"discovered_{entity_type}s"
        if key not in self.context:
            self.context[key] = []
        if isinstance(value, list):
            for v in value:
                if v and v not in self.context[key]:
                    self.context[key].append(v)
        elif value and value not in self.context[key]:
            self.context[key].append(value)

    def get_elapsed_seconds(self) -> int:
        """Get elapsed time since scan started."""
        return int(time.monotonic() - self._start_mono)

    @classmethod
    def load_from_disk(cls, request_id: str) -> "ScanSession | None":
        """
        Load a previous scan session from disk.

        Used by the 'resume' command.
        """
        meta_path = Path(settings.data_dir) / "requests" / request_id / "metadata.json"
        if not meta_path.exists():
            return None

        with open(meta_path) as f:
            data = json.load(f)

        target_type = TargetType(data["target_type"])
        session = cls(
            target=data["target"],
            target_type=target_type,
            target_inputs=data.get("target_inputs", {}),
        )
        session.request_id = request_id
        session.status = ScanStatus(data.get("status", "pending"))
        session.modules_executed = data.get("modules_executed", [])
        session.modules_failed = data.get("modules_failed", [])
        session.modules_skipped = data.get("modules_skipped", [])
        session.total_findings = data.get("total_findings", 0)
        return session
