"""
GitHub OSINT module.

Collects public intelligence from the GitHub API:
  - User profile (name, bio, company, location, follower counts, etc.)
  - Public repositories with language breakdown
  - Recent public events
  - Public gists
  - Committer email addresses extracted from recent commit history

Authenticated requests: 5,000 req/hr
Unauthenticated:          60 req/hr
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import aiohttp
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

_GITHUB_API = "https://api.github.com"


class GitHubAPIModule(BaseModule):
    """GitHub OSINT — profile, repos, events, gists, and email extraction."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="github_api",
            display_name="GitHub OSINT",
            description=(
                "Retrieves GitHub profile, repositories, gists, public events, "
                "and extracts committer email addresses from commit history."
            ),
            phase=ModulePhase.FAST_API,
            supported_targets=[
                TargetType.USERNAME,
                TargetType.PERSON,
                TargetType.EMAIL,
            ],
            requires_auth=False,  # Works without token at lower rate
            enabled_by_default=True,
            tags=["social", "github", "code", "email", "repos"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        # Strip leading @ if present
        username = target.lstrip("@")

        token = self._get_secret(settings.github_token)
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "GOD_EYE/1.0",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
            logger.debug("github_api_authenticated", username=username)
        else:
            logger.debug("github_api_unauthenticated", username=username)

        errors: list[str] = []
        warnings: list[str] = []

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers=headers,
        ) as session:
            # Step 1: Fetch the profile (required — abort if not found)
            try:
                profile = await self._fetch_profile(session, username)
            except APIError as exc:
                if exc.status_code == 404:
                    return ModuleResult.fail(f"GitHub user '{username}' not found")
                return ModuleResult.fail(str(exc))

            # Step 2: Fetch repos, events, gists in parallel
            repos_task = self._fetch_repos(session, username, errors)
            events_task = self._fetch_events(session, username, errors)
            gists_task = self._fetch_gists(session, username, errors)

            repos, events, gists = await asyncio.gather(
                repos_task, events_task, gists_task, return_exceptions=True
            )

            for result, label in ((repos, "repos"), (events, "events"), (gists, "gists")):
                if isinstance(result, Exception):
                    errors.append(f"Failed to fetch {label}: {result}")

            repos = repos if not isinstance(repos, Exception) else []
            events = events if not isinstance(events, Exception) else []
            gists = gists if not isinstance(gists, Exception) else []

            # Step 3: Extract emails from commits (limited to first 10 repos)
            commit_emails: set[str] = set()
            top_repos = repos[:10]  # type: ignore[index]

            email_tasks = [
                self._extract_emails_from_repo(session, username, repo["name"], errors)
                for repo in top_repos
                if isinstance(repo, dict) and repo.get("name")
            ]

            if email_tasks:
                email_results = await asyncio.gather(*email_tasks, return_exceptions=True)
                for result in email_results:
                    if isinstance(result, Exception):
                        errors.append(f"Email extraction error: {result}")
                    elif isinstance(result, set):
                        commit_emails.update(result)

        events_summary = self._summarise_events(events)  # type: ignore[arg-type]

        logger.info(
            "github_api_complete",
            username=username,
            repos=len(repos),  # type: ignore[arg-type]
            emails_found=len(commit_emails),
            gists=len(gists),  # type: ignore[arg-type]
        )

        return ModuleResult(
            success=True,
            data={
                "username": username,
                "profile": profile,
                "repos": repos,
                "gists_count": len(gists),  # type: ignore[arg-type]
                "commit_emails": list(commit_emails),
                "events_summary": events_summary,
            },
            errors=errors,
            warnings=warnings,
        )

    # ── API call methods ────────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(RateLimitError),
        reraise=True,
    )
    async def _fetch_profile(
        self,
        session: aiohttp.ClientSession,
        username: str,
    ) -> dict[str, Any]:
        """Fetch /users/{username} and return normalised profile dict."""
        url = f"{_GITHUB_API}/users/{username}"
        logger.debug("github_fetch_profile", username=username)

        async with session.get(url) as resp:
            if resp.status == 404:
                raise APIError("GitHub", 404, f"User '{username}' not found")
            if resp.status == 429:
                raise RateLimitError("GitHub")
            if resp.status == 401:
                raise APIError("GitHub", 401, "Invalid or missing GitHub token")
            if resp.status != 200:
                raise APIError("GitHub", resp.status, await resp.text())

            data = await resp.json()

        return {
            "name": data.get("name") or "",
            "bio": data.get("bio") or "",
            "company": data.get("company") or "",
            "location": data.get("location") or "",
            "email": data.get("email") or "",
            "blog": data.get("blog") or "",
            "twitter_username": data.get("twitter_username") or "",
            "public_repos": data.get("public_repos", 0),
            "public_gists": data.get("public_gists", 0),
            "followers": data.get("followers", 0),
            "following": data.get("following", 0),
            "created_at": data.get("created_at") or "",
            "updated_at": data.get("updated_at") or "",
            "avatar_url": data.get("avatar_url") or "",
            "html_url": data.get("html_url") or "",
            "type": data.get("type") or "User",
            "site_admin": data.get("site_admin", False),
        }

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(RateLimitError),
        reraise=True,
    )
    async def _fetch_repos(
        self,
        session: aiohttp.ClientSession,
        username: str,
        errors: list[str],
    ) -> list[dict[str, Any]]:
        """Fetch /users/{username}/repos sorted by last updated."""
        url = f"{_GITHUB_API}/users/{username}/repos"
        params = {"sort": "updated", "per_page": 30, "type": "owner"}

        logger.debug("github_fetch_repos", username=username)

        async with session.get(url, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("GitHub")
            if resp.status == 404:
                return []
            if resp.status != 200:
                errors.append(f"Repos fetch failed: HTTP {resp.status}")
                return []

            data = await resp.json()

        repos: list[dict[str, Any]] = []
        for repo in data:
            repos.append(
                {
                    "name": repo.get("name", ""),
                    "full_name": repo.get("full_name", ""),
                    "description": repo.get("description") or "",
                    "language": repo.get("language") or "",
                    "stars": repo.get("stargazers_count", 0),
                    "forks": repo.get("forks_count", 0),
                    "is_fork": repo.get("fork", False),
                    "is_private": repo.get("private", False),
                    "created_at": repo.get("created_at") or "",
                    "updated_at": repo.get("updated_at") or "",
                    "html_url": repo.get("html_url") or "",
                    "topics": repo.get("topics") or [],
                    "license": (repo.get("license") or {}).get("spdx_id") or "",
                    "size_kb": repo.get("size", 0),
                    "open_issues": repo.get("open_issues_count", 0),
                    "default_branch": repo.get("default_branch") or "main",
                }
            )

        return repos

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(RateLimitError),
        reraise=True,
    )
    async def _fetch_events(
        self,
        session: aiohttp.ClientSession,
        username: str,
        errors: list[str],
    ) -> list[dict[str, Any]]:
        """Fetch /users/{username}/events/public."""
        url = f"{_GITHUB_API}/users/{username}/events/public"
        params = {"per_page": 30}

        logger.debug("github_fetch_events", username=username)

        async with session.get(url, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("GitHub")
            if resp.status in (404, 403):
                return []
            if resp.status != 200:
                errors.append(f"Events fetch failed: HTTP {resp.status}")
                return []

            return await resp.json()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(RateLimitError),
        reraise=True,
    )
    async def _fetch_gists(
        self,
        session: aiohttp.ClientSession,
        username: str,
        errors: list[str],
    ) -> list[dict[str, Any]]:
        """Fetch /users/{username}/gists."""
        url = f"{_GITHUB_API}/users/{username}/gists"
        params = {"per_page": 30}

        logger.debug("github_fetch_gists", username=username)

        async with session.get(url, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("GitHub")
            if resp.status in (404, 403):
                return []
            if resp.status != 200:
                errors.append(f"Gists fetch failed: HTTP {resp.status}")
                return []

            return await resp.json()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(RateLimitError),
        reraise=True,
    )
    async def _extract_emails_from_repo(
        self,
        session: aiohttp.ClientSession,
        owner: str,
        repo: str,
        errors: list[str],
    ) -> set[str]:
        """
        Fetch the 10 most recent commits for a repo and extract committer emails.

        Returns a set of discovered email addresses.
        """
        url = f"{_GITHUB_API}/repos/{owner}/{repo}/commits"
        params = {"per_page": 10}

        logger.debug("github_fetch_commits", owner=owner, repo=repo)

        async with session.get(url, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("GitHub")
            if resp.status in (404, 403, 409):
                # 409 = empty repo
                return set()
            if resp.status != 200:
                return set()

            commits = await resp.json()

        emails: set[str] = set()
        email_pattern = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

        for commit_item in commits:
            if not isinstance(commit_item, dict):
                continue
            commit = commit_item.get("commit", {})

            # Extract from author
            author = commit.get("author", {}) or {}
            if email := author.get("email"):
                if (
                    email_pattern.match(email)
                    and not email.endswith("@users.noreply.github.com")
                ):
                    emails.add(email.lower())

            # Extract from committer
            committer = commit.get("committer", {}) or {}
            if email := committer.get("email"):
                if (
                    email_pattern.match(email)
                    and not email.endswith("@users.noreply.github.com")
                    and email != "noreply@github.com"
                ):
                    emails.add(email.lower())

        return emails

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _summarise_events(events: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Produce a compact summary of recent public events.

        Returns counts by event type and repos recently pushed to.
        """
        if not events:
            return {"total": 0, "by_type": {}, "recent_repos": []}

        type_counts: dict[str, int] = {}
        repos: list[str] = []

        for event in events:
            if not isinstance(event, dict):
                continue
            etype = event.get("type", "Unknown")
            type_counts[etype] = type_counts.get(etype, 0) + 1

            repo_info = event.get("repo", {}) or {}
            repo_name = repo_info.get("name", "")
            if repo_name and repo_name not in repos:
                repos.append(repo_name)

        return {
            "total": len(events),
            "by_type": type_counts,
            "recent_repos": repos[:10],
        }
