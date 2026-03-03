"""
Tests for the face selector UI module and orchestrator face confirmation checkpoint.
"""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest


class TestFaceSelectorResult:
    def test_default_creation(self):
        from app.ui.face_selector import FaceSelectorResult

        result = FaceSelectorResult()
        assert result.confirmed_indices == []
        assert result.confirmed_paths == []
        assert result.skipped is False

    def test_custom_creation(self):
        from app.ui.face_selector import FaceSelectorResult

        result = FaceSelectorResult(
            confirmed_indices=[0, 2],
            confirmed_paths=["/tmp/a.jpg", "/tmp/c.jpg"],
            skipped=False,
        )
        assert result.confirmed_indices == [0, 2]
        assert len(result.confirmed_paths) == 2

    def test_skipped_flag(self):
        from app.ui.face_selector import FaceSelectorResult

        result = FaceSelectorResult(skipped=True)
        assert result.skipped is True


class TestSelectFaces:
    def test_empty_images_returns_skipped(self):
        from app.ui.face_selector import select_faces

        result = select_faces([], mode="auto")
        assert result.skipped is True
        assert result.confirmed_indices == []

    def test_disabled_mode_returns_all(self):
        from app.ui.face_selector import select_faces

        images = [
            {"file_path": "/tmp/a.jpg", "platform": "linkedin"},
            {"file_path": "/tmp/b.jpg", "platform": "instagram"},
        ]
        result = select_faces(images, mode="disabled")
        assert result.skipped is True
        assert result.confirmed_indices == [0, 1]
        assert len(result.confirmed_paths) == 2


class TestSelectFacesRich:
    def test_all_selection(self, monkeypatch):
        from app.ui.face_selector import select_faces_rich

        monkeypatch.setattr("rich.prompt.Prompt.ask", lambda *a, **kw: "all")

        images = [
            {"file_path": "/tmp/a.jpg", "platform": "linkedin"},
            {"file_path": "/tmp/b.jpg", "platform": "instagram"},
        ]
        result = select_faces_rich(images)
        assert result.confirmed_indices == [0, 1]
        assert result.skipped is False

    def test_specific_indices(self, monkeypatch):
        from app.ui.face_selector import select_faces_rich

        monkeypatch.setattr("rich.prompt.Prompt.ask", lambda *a, **kw: "0,1")

        images = [
            {"file_path": "/tmp/a.jpg", "platform": "linkedin"},
            {"file_path": "/tmp/b.jpg", "platform": "instagram"},
            {"file_path": "/tmp/c.jpg", "platform": "facebook"},
        ]
        result = select_faces_rich(images)
        assert result.confirmed_indices == [0, 1]
        assert result.skipped is False

    def test_skip_selection(self, monkeypatch):
        from app.ui.face_selector import select_faces_rich

        monkeypatch.setattr("rich.prompt.Prompt.ask", lambda *a, **kw: "skip")

        images = [
            {"file_path": "/tmp/a.jpg", "platform": "linkedin"},
        ]
        result = select_faces_rich(images)
        assert result.skipped is True
        assert result.confirmed_indices == [0]

    def test_invalid_indices_fallback_to_all(self, monkeypatch):
        from app.ui.face_selector import select_faces_rich

        monkeypatch.setattr("rich.prompt.Prompt.ask", lambda *a, **kw: "abc,xyz")

        images = [
            {"file_path": "/tmp/a.jpg", "platform": "test"},
        ]
        result = select_faces_rich(images)
        # Invalid indices → fallback to all
        assert result.skipped is True
        assert result.confirmed_indices == [0]


class TestBuildThumbnailPayloads:
    def test_with_real_image(self, tmp_path: Path):
        """Test thumbnail generation with a real (tiny) PIL image."""
        pytest.importorskip("PIL")
        from PIL import Image

        from app.ui.face_selector import build_thumbnail_payloads

        # Create a tiny test image
        img = Image.new("RGB", (10, 10), color="red")
        img_path = tmp_path / "test.jpg"
        img.save(str(img_path))

        images = [{"file_path": str(img_path), "platform": "test"}]
        payloads = build_thumbnail_payloads(images)

        assert len(payloads) == 1
        assert payloads[0]["index"] == 0
        assert payloads[0]["filename"] == "test.jpg"
        assert payloads[0]["platform"] == "test"
        assert payloads[0]["thumbnail_b64"] is not None
        assert len(payloads[0]["thumbnail_b64"]) > 0

    def test_with_missing_file(self, tmp_path: Path):
        """Test thumbnail generation with a nonexistent file."""
        from app.ui.face_selector import build_thumbnail_payloads

        images = [{"file_path": str(tmp_path / "nonexistent.jpg"), "platform": "test"}]
        payloads = build_thumbnail_payloads(images)

        assert len(payloads) == 1
        assert payloads[0]["thumbnail_b64"] is None

    def test_empty_images(self):
        from app.ui.face_selector import build_thumbnail_payloads

        payloads = build_thumbnail_payloads([])
        assert payloads == []


class TestCanUseTkinter:
    def test_returns_bool(self):
        from app.ui.face_selector import _can_use_tkinter

        result = _can_use_tkinter()
        assert isinstance(result, bool)


class TestFaceConfirmationCheckpoint:
    @pytest.mark.asyncio
    async def test_checkpoint_calls_callback(self):
        from app.engine.orchestrator import Orchestrator
        from app.engine.session import ScanSession

        callback = AsyncMock(return_value={"confirmed_indices": [0, 2]})
        orchestrator = Orchestrator(interaction_callback=callback)

        session = ScanSession.__new__(ScanSession)
        session.request_id = "test_req_123"
        session.context = {
            "discovered_images": [
                {"file_path": "/tmp/a.jpg", "platform": "linkedin"},
                {"file_path": "/tmp/b.jpg", "platform": "instagram"},
                {"file_path": "/tmp/c.jpg", "platform": "facebook"},
            ],
            "module_results": {},
        }

        with patch("app.engine.orchestrator.get_module_setting", return_value="auto"):
            await orchestrator._face_confirmation_checkpoint(session)

        callback.assert_called_once()
        assert session.context["confirmed_face_images"] == [
            {"file_path": "/tmp/a.jpg", "platform": "linkedin"},
            {"file_path": "/tmp/c.jpg", "platform": "facebook"},
        ]
        assert session.context["reference_image"] == "/tmp/a.jpg"

    @pytest.mark.asyncio
    async def test_checkpoint_skips_when_no_images(self):
        from app.engine.orchestrator import Orchestrator
        from app.engine.session import ScanSession

        callback = AsyncMock()
        orchestrator = Orchestrator(interaction_callback=callback)

        session = ScanSession.__new__(ScanSession)
        session.request_id = "test_req_456"
        session.context = {"discovered_images": [], "module_results": {}}

        await orchestrator._face_confirmation_checkpoint(session)
        callback.assert_not_called()

    @pytest.mark.asyncio
    async def test_checkpoint_skips_when_no_callback(self):
        from app.engine.orchestrator import Orchestrator
        from app.engine.session import ScanSession

        orchestrator = Orchestrator()

        session = ScanSession.__new__(ScanSession)
        session.request_id = "test_req_789"
        session.context = {
            "discovered_images": [
                {"file_path": "/tmp/a.jpg", "platform": "test"},
            ],
            "module_results": {},
        }

        with patch("app.engine.orchestrator.get_module_setting", return_value="auto"):
            await orchestrator._face_confirmation_checkpoint(session)

        # Should not crash or set confirmed_face_images
        assert "confirmed_face_images" not in session.context

    @pytest.mark.asyncio
    async def test_checkpoint_skips_when_disabled(self):
        from app.engine.orchestrator import Orchestrator
        from app.engine.session import ScanSession

        callback = AsyncMock()
        orchestrator = Orchestrator(interaction_callback=callback)

        session = ScanSession.__new__(ScanSession)
        session.request_id = "test_req_disabled"
        session.context = {
            "discovered_images": [
                {"file_path": "/tmp/a.jpg", "platform": "test"},
            ],
            "module_results": {},
        }

        with patch("app.engine.orchestrator.get_module_setting", return_value="disabled"):
            await orchestrator._face_confirmation_checkpoint(session)

        callback.assert_not_called()
