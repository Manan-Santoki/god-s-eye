"""
Tests for the Google Cloud Vision face detection module.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from app.core.constants import ModulePhase, TargetType
from app.modules.visual.google_vision_faces import GoogleVisionFacesModule


class TestGoogleVisionFacesMetadata:
    def test_name(self):
        m = GoogleVisionFacesModule()
        meta = m.metadata()
        assert meta.name == "google_vision_faces"

    def test_phase(self):
        m = GoogleVisionFacesModule()
        meta = m.metadata()
        assert meta.phase == ModulePhase.IMAGE_PROCESSING

    def test_requires_auth(self):
        m = GoogleVisionFacesModule()
        meta = m.metadata()
        assert meta.requires_auth is True

    def test_supported_targets(self):
        m = GoogleVisionFacesModule()
        meta = m.metadata()
        assert TargetType.PERSON in meta.supported_targets
        assert TargetType.USERNAME in meta.supported_targets


class TestGoogleVisionFacesValidate:
    @pytest.mark.asyncio
    async def test_validate_false_without_api_key(self, monkeypatch):
        monkeypatch.setattr(
            "app.modules.visual.google_vision_faces.settings",
            type("S", (), {"has_api_key": staticmethod(lambda k: False)})(),
        )
        m = GoogleVisionFacesModule()
        assert await m.validate("test", TargetType.PERSON) is False

    @pytest.mark.asyncio
    async def test_validate_true_with_api_key(self, monkeypatch):
        monkeypatch.setattr(
            "app.modules.visual.google_vision_faces.settings",
            type("S", (), {"has_api_key": staticmethod(lambda k: True)})(),
        )
        m = GoogleVisionFacesModule()
        assert await m.validate("test", TargetType.PERSON) is True


class TestGoogleVisionFacesRun:
    @pytest.mark.asyncio
    async def test_run_fails_without_api_key(self):
        m = GoogleVisionFacesModule()
        with patch(
            "app.modules.visual.google_vision_faces._get_api_key", return_value=None
        ):
            result = await m.run(
                target="test",
                target_type=TargetType.PERSON,
                context={"discovered_images": []},
            )
        assert result.success is False
        assert "not configured" in result.errors[0]

    @pytest.mark.asyncio
    async def test_run_no_images(self):
        m = GoogleVisionFacesModule()
        with patch(
            "app.modules.visual.google_vision_faces._get_api_key",
            return_value="fake-key",
        ):
            result = await m.run(
                target="test",
                target_type=TargetType.PERSON,
                context={"discovered_images": []},
            )
        assert result.success is True
        assert result.data["total_images_processed"] == 0


class TestCollectImagePaths:
    def test_with_real_file(self, tmp_path: Path):
        img = tmp_path / "face.jpg"
        img.write_bytes(b"fake jpeg data")

        paths = GoogleVisionFacesModule._collect_image_paths(
            [{"file_path": str(img)}]
        )
        assert len(paths) == 1
        assert paths[0] == img

    def test_with_string_path(self, tmp_path: Path):
        img = tmp_path / "face.png"
        img.write_bytes(b"fake png data")

        paths = GoogleVisionFacesModule._collect_image_paths([str(img)])
        assert len(paths) == 1

    def test_ignores_missing_files(self, tmp_path: Path):
        paths = GoogleVisionFacesModule._collect_image_paths(
            [{"file_path": str(tmp_path / "nonexistent.jpg")}]
        )
        assert len(paths) == 0

    def test_ignores_non_image_extensions(self, tmp_path: Path):
        txt = tmp_path / "notes.txt"
        txt.write_text("hello")

        paths = GoogleVisionFacesModule._collect_image_paths([str(txt)])
        assert len(paths) == 0

    def test_empty_input(self):
        paths = GoogleVisionFacesModule._collect_image_paths([])
        assert paths == []
