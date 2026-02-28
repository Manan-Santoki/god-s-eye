"""
GOD_EYE FastAPI REST API Server

Provides HTTP/WebSocket endpoints for the GOD_EYE platform.
Useful for web dashboards, integrations, and headless automation.

Start: uvicorn app.main:app --host 0.0.0.0 --port 8000
"""

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from app.core.config import settings
from app.core.constants import TargetType
from app.core.logging import get_logger, setup_logging

logger = get_logger(__name__)

# Track background scan tasks
_running_scans: dict[str, asyncio.Task] = {}
_ws_connections: dict[str, list[WebSocket]] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    setup_logging(settings.log_level, settings.log_format, settings.data_dir / "logs")
    logger.info("god_eye_api_starting", version="1.0.0")

    # Initialize database connections
    try:
        from app.database.sqlite_cache import get_cache
        await get_cache()
        logger.info("sqlite_ready")
    except Exception as e:
        logger.warning("sqlite_init_failed", error=str(e))

    yield

    # Cleanup
    for task in _running_scans.values():
        task.cancel()
    logger.info("god_eye_api_shutdown")


app = FastAPI(
    title="GOD_EYE OSINT API",
    description="Open Source Intelligence Platform REST API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request/Response Models ──────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    target_type: str  # email | username | person | phone | domain | ip | company
    target_inputs: dict[str, str] = {}
    phases: Optional[list[int]] = None
    modules: Optional[list[str]] = None
    enable_ai: bool = True


class ScanResponse(BaseModel):
    request_id: str
    status: str
    message: str


class HealthResponse(BaseModel):
    status: str
    services: dict[str, bool]
    modules_count: int
    version: str = "1.0.0"


# ── Endpoints ────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check() -> HealthResponse:
    """Check health of all GOD_EYE services."""
    services: dict[str, bool] = {}

    # Neo4j
    try:
        from app.database.neo4j_client import Neo4jClient
        client = Neo4jClient()
        await client.connect()
        services["neo4j"] = await client.health_check()
        await client.disconnect()
    except Exception:
        services["neo4j"] = False

    # Redis
    try:
        from app.database.redis_client import RedisClient
        redis = RedisClient()
        await redis.connect()
        services["redis"] = await redis.health_check()
        await redis.disconnect()
    except Exception:
        services["redis"] = False

    # Modules
    modules_count = 0
    try:
        from app.modules import get_registry
        modules_count = len(get_registry())
        services["modules"] = modules_count > 0
    except Exception:
        services["modules"] = False

    overall = all(services.values())
    return HealthResponse(
        status="healthy" if overall else "degraded",
        services=services,
        modules_count=modules_count,
    )


@app.get("/modules", tags=["System"])
async def list_modules() -> list[dict[str, Any]]:
    """List all registered intelligence modules."""
    try:
        from app.modules import list_modules as _list_modules
        return _list_modules()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan", response_model=ScanResponse, tags=["Scanning"])
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
) -> ScanResponse:
    """
    Start an OSINT scan in the background.

    Returns immediately with a request_id to track progress.
    Poll GET /scan/{request_id} or connect to WebSocket /ws/{request_id}.
    """
    try:
        target_type = TargetType(request.target_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid target_type. Must be: {[t.value for t in TargetType]}",
        )

    # Override AI if disabled
    if not request.enable_ai:
        settings.enable_ai_correlation = False
        settings.enable_ai_reports = False

    # Generate request_id before starting background task
    from app.engine.session import generate_request_id
    request_id = generate_request_id(request.target)

    background_tasks.add_task(
        _run_scan_background,
        request.target,
        target_type,
        request.target_inputs,
        request.phases,
        request.modules,
        request_id,
    )

    return ScanResponse(
        request_id=request_id,
        status="started",
        message=f"Scan started. Poll GET /scan/{request_id} for status.",
    )


async def _run_scan_background(
    target: str,
    target_type: TargetType,
    target_inputs: dict,
    phases: list | None,
    module_filter: list | None,
    request_id: str,
) -> None:
    """Execute scan in background and notify WebSocket subscribers."""
    try:
        from app.engine.orchestrator import Orchestrator
        orchestrator = Orchestrator()
        session = await orchestrator.run_scan(
            target=target,
            target_type=target_type,
            target_inputs=target_inputs,
            phases=phases,
            module_filter=module_filter,
            show_progress=False,
        )

        # Notify WebSocket subscribers
        await _broadcast_progress(request_id, {
            "status": session.status.value,
            "findings": session.total_findings,
            "risk_score": session.context.get("risk_score"),
        })

    except Exception as e:
        logger.error("background_scan_failed", request_id=request_id, error=str(e))
        await _broadcast_progress(request_id, {"status": "failed", "error": str(e)})
    finally:
        _running_scans.pop(request_id, None)


@app.get("/scan/{request_id}", tags=["Scanning"])
async def get_scan_status(request_id: str) -> dict[str, Any]:
    """Get scan status and metadata."""
    from app.core.config import settings
    from pathlib import Path

    meta_file = Path(settings.data_dir) / "requests" / request_id / "metadata.json"
    if not meta_file.exists():
        raise HTTPException(status_code=404, detail=f"Scan not found: {request_id}")

    with open(meta_file) as f:
        return json.load(f)


@app.get("/scan/{request_id}/results", tags=["Scanning"])
async def get_scan_results(request_id: str) -> dict[str, Any]:
    """Get full scan results including all module outputs."""
    from app.core.config import settings
    from pathlib import Path

    scan_dir = Path(settings.data_dir) / "requests" / request_id
    if not scan_dir.exists():
        raise HTTPException(status_code=404, detail=f"Scan not found: {request_id}")

    meta_file = scan_dir / "metadata.json"
    results: dict[str, Any] = {}

    if meta_file.exists():
        with open(meta_file) as f:
            results["metadata"] = json.load(f)

    raw_data: dict[str, Any] = {}
    raw_dir = scan_dir / "raw_data"
    if raw_dir.exists():
        for f in raw_dir.glob("*.json"):
            with open(f) as fp:
                raw_data[f.stem] = json.load(fp)
    results["module_results"] = raw_data

    return results


@app.get("/scan/{request_id}/report", tags=["Scanning"])
async def get_scan_report(request_id: str, format: str = "html") -> Any:
    """Download a generated report in the specified format."""
    from app.core.config import settings
    from pathlib import Path

    reports_dir = Path(settings.data_dir) / "requests" / request_id / "reports"
    file_map = {
        "html": "full_report.html",
        "pdf": "full_report.pdf",
        "json": "technical_data.json",
        "markdown": "full_report.md",
        "csv": "export.csv",
    }

    filename = file_map.get(format, "full_report.html")
    report_path = reports_dir / filename

    if not report_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Report not found: {format}. Run the report command first.",
        )

    return FileResponse(str(report_path), filename=filename)


@app.delete("/scan/{request_id}", tags=["Scanning"])
async def delete_scan(request_id: str) -> dict[str, str]:
    """Delete all data for a scan."""
    import shutil
    from app.core.config import settings
    from pathlib import Path

    scan_dir = Path(settings.data_dir) / "requests" / request_id
    if not scan_dir.exists():
        raise HTTPException(status_code=404, detail=f"Scan not found: {request_id}")

    shutil.rmtree(str(scan_dir))
    logger.info("scan_deleted", request_id=request_id)
    return {"message": f"Scan {request_id} deleted"}


@app.get("/scans", tags=["Scanning"])
async def list_scans(limit: int = 20, status: Optional[str] = None) -> list[dict]:
    """List all scans with optional status filter."""
    from app.database.sqlite_cache import get_cache
    cache = await get_cache()
    return await cache.list_scans(limit=limit, status=status)


@app.post("/scan/{request_id}/cancel", tags=["Scanning"])
async def cancel_scan(request_id: str) -> dict[str, str]:
    """Cancel a running scan."""
    task = _running_scans.get(request_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"No running scan: {request_id}")
    task.cancel()
    return {"message": f"Scan {request_id} cancelled"}


# ── WebSocket ────────────────────────────────────────────────────

@app.websocket("/ws/{request_id}")
async def websocket_endpoint(websocket: WebSocket, request_id: str) -> None:
    """
    Real-time scan progress updates via WebSocket.

    Connect to ws://localhost:8000/ws/{request_id} to receive live updates.
    """
    await websocket.accept()
    if request_id not in _ws_connections:
        _ws_connections[request_id] = []
    _ws_connections[request_id].append(websocket)

    try:
        # Send current status if scan exists
        from app.database.redis_client import get_redis
        try:
            redis = await get_redis()
            progress = await redis.get_scan_progress(request_id)
            if progress:
                await websocket.send_json(progress)
        except Exception:
            pass

        # Keep alive until client disconnects
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                await websocket.send_json({"ping": True})
    except WebSocketDisconnect:
        pass
    finally:
        if request_id in _ws_connections:
            _ws_connections[request_id].remove(websocket)


async def _broadcast_progress(request_id: str, data: dict) -> None:
    """Send progress update to all WebSocket subscribers."""
    ws_list = _ws_connections.get(request_id, [])
    dead = []
    for ws in ws_list:
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        ws_list.remove(ws)


# ── Root ─────────────────────────────────────────────────────────

@app.get("/", tags=["System"])
async def root() -> dict[str, str]:
    return {
        "name": "GOD_EYE OSINT API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
    }
