"""
GOD_EYE FastAPI REST API Server

Provides HTTP/WebSocket endpoints for the GOD_EYE platform.
Useful for web dashboards, integrations, and headless automation.

Start: uvicorn app.main:app --host 0.0.0.0 --port 8000
"""

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app import __version__
from app.core.config import settings
from app.core.constants import TargetType
from app.core.logging import get_logger, setup_logging

logger = get_logger(__name__)

# Track background scan tasks
_running_scans: dict[str, asyncio.Task[None]] = {}
_ws_connections: dict[str, list[WebSocket]] = {}

# Face selection state for API mode
_pending_face_selections: dict[str, asyncio.Event] = {}
_face_selection_results: dict[str, dict[str, Any]] = {}
_pending_face_payloads: dict[str, list[dict[str, Any]]] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    setup_logging(settings.log_level, settings.log_format, settings.data_dir / "logs")
    logger.info("god_eye_api_starting", version=__version__)

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
    version=__version__,
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
    # Narrowing filters for common-name disambiguation
    work: str | None = None  # Target's employer (e.g. "BlackRock")
    location: str | None = None  # Target's city/country (e.g. "Mumbai")
    phases: list[int] | None = None
    modules: list[str] | None = None
    enable_ai: bool = True


class ScanResponse(BaseModel):
    request_id: str
    status: str
    message: str


class HealthResponse(BaseModel):
    status: str
    services: dict[str, bool]
    modules_count: int
    version: str = __version__


class FaceSelectionRequest(BaseModel):
    confirmed_indices: list[int]


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

    from app.engine.session import generate_request_id

    # Merge work/location into target_inputs so all modules can access them
    enriched_inputs = dict(request.target_inputs)
    if request.work:
        enriched_inputs["work"] = request.work
    if request.location:
        enriched_inputs["location"] = request.location

    request_id = generate_request_id(request.target)
    task = asyncio.create_task(
        _run_scan_background(
            request.target,
            target_type,
            enriched_inputs,
            request.phases,
            request.modules,
            request.enable_ai,
            request_id,
        ),
        name=f"scan:{request_id}",
    )
    _running_scans[request_id] = task
    await _publish_progress(
        request_id,
        {
            "status": "started",
            "phase": 0,
            "phase_name": "queued",
            "completed_modules": 0,
            "total_modules": 0,
        },
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
    enable_ai: bool,
    request_id: str,
) -> None:
    """Execute scan in background and notify WebSocket subscribers."""
    try:
        from app.engine.orchestrator import Orchestrator

        async def api_interaction_callback(
            interaction_type: str, payload: dict[str, Any]
        ) -> dict[str, Any]:
            if interaction_type != "face_selection_required":
                return {}

            images = payload.get("images", [])
            if not images:
                return {"confirmed_indices": []}

            # Generate thumbnails for WebSocket/API delivery
            from app.ui.face_selector import build_thumbnail_payloads

            loop = asyncio.get_event_loop()
            thumbnails = await loop.run_in_executor(
                None, build_thumbnail_payloads, images
            )

            # Store payloads for the GET endpoint
            _pending_face_payloads[request_id] = thumbnails

            # Notify WebSocket clients
            await _publish_progress(
                request_id,
                {
                    "type": "face_selection_required",
                    "images": thumbnails,
                    "image_count": len(images),
                },
            )

            # Wait for user response via POST endpoint
            event = asyncio.Event()
            _pending_face_selections[request_id] = event

            try:
                timeout = 300  # seconds
                try:
                    from app.core.config import get_module_setting

                    timeout = int(
                        get_module_setting(
                            "visual", "face_selector", "timeout_seconds", 300
                        )
                        or 300
                    )
                except Exception:
                    pass

                await asyncio.wait_for(event.wait(), timeout=timeout)
                result = _face_selection_results.get(request_id, {})
                return result
            except TimeoutError:
                logger.warning(
                    "face_selection_timeout",
                    request_id=request_id,
                    timeout=timeout,
                )
                # Auto-continue with all images on timeout
                return {
                    "confirmed_indices": list(range(len(images)))
                }
            finally:
                _pending_face_selections.pop(request_id, None)
                _face_selection_results.pop(request_id, None)
                _pending_face_payloads.pop(request_id, None)

        orchestrator = Orchestrator(
            progress_callback=lambda payload: _publish_progress(request_id, payload),
            interaction_callback=api_interaction_callback,
        )
        session = await orchestrator.run_scan(
            target=target,
            target_type=target_type,
            target_inputs=target_inputs,
            phases=phases,
            module_filter=module_filter,
            show_progress=False,
            request_id=request_id,
            enable_ai_correlation=enable_ai,
            enable_ai_reports=enable_ai,
        )

        await _publish_progress(
            request_id,
            {
                "status": session.status.value,
                "findings": session.total_findings,
                "risk_score": session.context.get("risk_score"),
            },
        )

    except Exception as e:
        logger.error("background_scan_failed", request_id=request_id, error=str(e))
        await _publish_progress(request_id, {"status": "failed", "error": str(e)})
    finally:
        _running_scans.pop(request_id, None)


@app.get("/scan/{request_id}", tags=["Scanning"])
async def get_scan_status(request_id: str) -> dict[str, Any]:
    """Get scan status and metadata."""
    from pathlib import Path

    from app.core.config import settings

    meta_file = Path(settings.data_dir) / "requests" / request_id / "metadata.json"
    if not meta_file.exists():
        raise HTTPException(status_code=404, detail=f"Scan not found: {request_id}")

    with open(meta_file) as f:
        return json.load(f)


@app.get("/scan/{request_id}/results", tags=["Scanning"])
async def get_scan_results(request_id: str) -> dict[str, Any]:
    """Get full scan results including all module outputs."""
    from pathlib import Path

    from app.core.config import settings

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
    from pathlib import Path

    from app.core.config import settings

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
    from pathlib import Path

    from app.core.config import settings

    scan_dir = Path(settings.data_dir) / "requests" / request_id
    if not scan_dir.exists():
        raise HTTPException(status_code=404, detail=f"Scan not found: {request_id}")

    shutil.rmtree(str(scan_dir))
    logger.info("scan_deleted", request_id=request_id)
    return {"message": f"Scan {request_id} deleted"}


@app.get("/scans", tags=["Scanning"])
async def list_scans(limit: int = 20, status: str | None = None) -> list[dict]:
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
    await _publish_progress(request_id, {"status": "cancel_requested"})
    return {"message": f"Scan {request_id} cancelled"}


# ── Face Selection Endpoints ──────────────────────────────────────


@app.get("/scan/{request_id}/pending-faces", tags=["Scanning"])
async def get_pending_faces(request_id: str) -> dict[str, Any]:
    """Get pending face selection thumbnails for a scan."""
    payloads = _pending_face_payloads.get(request_id)
    if payloads is None:
        raise HTTPException(
            status_code=404,
            detail=f"No pending face selection for scan: {request_id}",
        )
    return {"request_id": request_id, "images": payloads}


@app.post("/scan/{request_id}/select-faces", tags=["Scanning"])
async def select_faces(
    request_id: str,
    request: FaceSelectionRequest,
) -> dict[str, str]:
    """Submit face selection for a pending scan."""
    event = _pending_face_selections.get(request_id)
    if not event:
        raise HTTPException(
            status_code=404,
            detail=f"No pending face selection for scan: {request_id}",
        )

    _face_selection_results[request_id] = {
        "confirmed_indices": request.confirmed_indices,
    }
    event.set()

    return {"message": f"Face selection submitted for scan {request_id}"}


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
            except TimeoutError:
                await websocket.send_json({"ping": True})
    except WebSocketDisconnect:
        pass
    finally:
        if request_id in _ws_connections:
            _ws_connections[request_id].remove(websocket)


async def _publish_progress(request_id: str, data: dict[str, Any]) -> None:
    """Send progress updates to WebSocket clients and Redis."""
    try:
        from app.database.redis_client import get_redis

        redis = await get_redis()
        await redis.publish_progress(request_id, data)
    except Exception:
        pass

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
        "version": __version__,
        "docs": "/docs",
        "health": "/health",
    }
