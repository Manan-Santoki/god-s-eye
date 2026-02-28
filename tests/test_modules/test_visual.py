"""
Tests for visual/image processing modules.
"""

from pathlib import Path


class TestReverseImageSearch:
    def test_collect_image_paths_accepts_downloaded_image_dicts(self, tmp_path: Path):
        from app.modules.visual.reverse_image import ReverseImageSearch

        image_path = tmp_path / "avatar.jpg"
        image_path.write_bytes(b"fake")

        paths = ReverseImageSearch._collect_image_paths(
            [
                {"file_path": str(image_path), "url": "https://example.com/avatar.jpg"},
                str(image_path),
            ]
        )

        assert paths[0] == image_path
        assert image_path in paths


class TestAIVisionAnalyzer:
    """Tests for the AI vision analyzer module."""

    def test_metadata(self):
        from app.modules.visual.ai_vision_analyzer import AIVisionAnalyzerModule
        from app.core.constants import ModulePhase

        m = AIVisionAnalyzerModule()
        meta = m.metadata()
        assert meta.name == "ai_vision_analyzer"
        assert meta.phase == ModulePhase.IMAGE_PROCESSING
        assert meta.enabled_by_default is True

    def test_parse_vision_response_valid_json(self):
        from app.modules.visual.ai_vision_analyzer import AIVisionAnalyzerModule

        result = AIVisionAnalyzerModule._parse_vision_response(
            '{"names": ["John Doe"], "emails": ["john@example.com"], "confidence": "high"}'
        )
        assert result["names"] == ["John Doe"]
        assert result["emails"] == ["john@example.com"]
        assert result["confidence"] == "high"

    def test_parse_vision_response_json_in_markdown(self):
        from app.modules.visual.ai_vision_analyzer import AIVisionAnalyzerModule

        content = '```json\n{"names": ["Jane Doe"]}\n```'
        result = AIVisionAnalyzerModule._parse_vision_response(content)
        assert result["names"] == ["Jane Doe"]

    def test_parse_vision_response_fallback(self):
        from app.modules.visual.ai_vision_analyzer import AIVisionAnalyzerModule

        result = AIVisionAnalyzerModule._parse_vision_response("not json at all")
        assert "visible_content_summary" in result
        assert result["confidence"] == "low"

    def test_collect_images_from_context_screenshots_dir(self, tmp_path: Path):
        from app.modules.visual.ai_vision_analyzer import AIVisionAnalyzerModule
        from unittest.mock import patch

        screenshots_dir = tmp_path / "screenshots"
        screenshots_dir.mkdir()
        (screenshots_dir / "snapshot_01_test.png").write_bytes(b"PNG_DATA")

        request_id = "req_test_123"
        data_dir = tmp_path

        context = {
            "request_id": request_id,
            "module_results": {},
        }

        with patch("app.modules.visual.ai_vision_analyzer.settings") as mock_settings:
            mock_settings.enable_ai_vision = True
            mock_settings.data_dir = tmp_path
            # Build expected path
            expected_dir = tmp_path / "requests" / request_id / "screenshots"
            expected_dir.mkdir(parents=True, exist_ok=True)
            (expected_dir / "snapshot_01_test.png").write_bytes(b"PNG_DATA")

            m = AIVisionAnalyzerModule()
            images = m._collect_images(context)

        paths = [img["path"] for img in images]
        assert any("snapshot_01_test.png" in p for p in paths)

    def test_collect_images_from_web_snapshot_results(self, tmp_path: Path):
        from app.modules.visual.ai_vision_analyzer import AIVisionAnalyzerModule

        screenshot_path = str(tmp_path / "shot1.png")
        (tmp_path / "shot1.png").write_bytes(b"PNG")

        context = {
            "request_id": "req_xyz",
            "module_results": {
                "web_snapshot": {
                    "screenshots": [
                        {"screenshot_path": screenshot_path, "url": "https://linkedin.com/in/user"}
                    ]
                }
            },
        }

        m = AIVisionAnalyzerModule()
        images = m._collect_images(context)
        assert any(img["path"] == screenshot_path for img in images)

    def test_collect_images_deduplicates(self, tmp_path: Path):
        from app.modules.visual.ai_vision_analyzer import AIVisionAnalyzerModule

        screenshot_path = str(tmp_path / "shot.png")
        (tmp_path / "shot.png").write_bytes(b"PNG")

        context = {
            "request_id": "req_xyz",
            "module_results": {
                "web_snapshot": {
                    "screenshots": [
                        {"screenshot_path": screenshot_path},
                        {"screenshot_path": screenshot_path},
                    ]
                }
            },
        }

        m = AIVisionAnalyzerModule()
        images = m._collect_images(context)
        paths = [img["path"] for img in images if img["path"] == screenshot_path]
        assert len(paths) == 1

    def test_collect_images_linkedin_profiles(self, tmp_path: Path):
        from app.modules.visual.ai_vision_analyzer import AIVisionAnalyzerModule

        screenshot_path = str(tmp_path / "linkedin_john.png")
        (tmp_path / "linkedin_john.png").write_bytes(b"PNG")

        context = {
            "request_id": "req_xyz",
            "module_results": {
                "linkedin_scraper": {
                    "profiles": [
                        {
                            "screenshot_path": screenshot_path,
                            "profile_url": "https://linkedin.com/in/john",
                        }
                    ]
                }
            },
        }

        m = AIVisionAnalyzerModule()
        images = m._collect_images(context)
        assert any(img["path"] == screenshot_path for img in images)

    import pytest

    @pytest.mark.asyncio
    async def test_run_returns_gracefully_without_api_key(self, monkeypatch):
        from app.modules.visual.ai_vision_analyzer import AIVisionAnalyzerModule
        from app.core.constants import TargetType

        monkeypatch.setenv("OPENROUTER_API_KEY", "")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "")
        monkeypatch.setenv("OPENAI_API_KEY", "")

        m = AIVisionAnalyzerModule()
        result = await m.run(
            target="test@example.com",
            target_type=TargetType.EMAIL,
            context={"request_id": "req_test", "module_results": {}},
        )
        # Should fail gracefully, not crash
        assert result is not None
