"""
Tests for report-generation evidence summaries.
"""

from pathlib import Path


def test_search_activity_summary_uses_actual_query_reports(scan_session, tmp_path: Path):
    from app.ai.report_generator import ReportGenerator

    scan_session.modules_executed = ["serpapi_search", "duckduckgo", "wayback"]
    scan_session.context["module_results"]["serpapi_search"] = {
        "total_results": 0,
        "query_reports": [
            {
                "query_type": "primary",
                "query": '"John Doe" "john@example.com"',
                "results_returned": 0,
                "reported_total_results": 0,
            }
        ],
    }
    scan_session.context["module_results"]["duckduckgo"] = {
        "web_results": [],
        "related_topics": [],
    }
    scan_session.context["module_results"]["wayback"] = {
        "has_archives": False,
        "total_snapshots": 0,
    }
    scan_session.request_log_path = tmp_path / "request_log.log"
    scan_session.request_log_path.write_text(
        '2026-02-28T00:00:00+00:00 module="serpapi_search" event="request" query="\\"John Doe\\" \\"john@example.com\\""\n',
        encoding="utf-8",
    )

    summary = ReportGenerator()._build_search_activity_text(scan_session)

    assert "serpapi_search" in summary
    assert '"John Doe" "john@example.com"' in summary
    assert "results_returned=0" in summary
    assert "duckduckgo web_results=0 related_topics=0" in summary
    assert "wayback has_archives=False total_snapshots=0" in summary


def test_image_activity_summary_distinguishes_no_execution(scan_session):
    from app.ai.report_generator import ReportGenerator

    summary = ReportGenerator()._build_image_activity_text(scan_session)

    assert summary == "No image modules executed and no image evidence collected."
