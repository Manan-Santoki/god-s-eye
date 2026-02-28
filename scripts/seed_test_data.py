#!/usr/bin/env python3
"""
Seed test data for GOD_EYE development and testing.

Creates synthetic scan results, entity graphs, and cache entries so you can
test the UI and reports without making real API calls.

Usage:
  python scripts/seed_test_data.py
  python scripts/seed_test_data.py --target-type email --count 5
  python scripts/seed_test_data.py --clear
"""

import argparse
import asyncio
import json
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# ── Synthetic data pool ───────────────────────────────────────────────────────

FAKE_NAMES = [
    "Alice Johnson",
    "Bob Smith",
    "Carol Williams",
    "David Brown",
    "Eve Davis",
    "Frank Wilson",
    "Grace Moore",
    "Henry Taylor",
]
FAKE_EMAILS = [
    "alice.johnson@gmail.com",
    "bob.smith@outlook.com",
    "carol.w@yahoo.com",
    "david.b@protonmail.com",
    "eve.davis@icloud.com",
]
FAKE_USERNAMES = ["alice_j", "bobsmith", "carol_w", "davbrown", "evedavis"]
FAKE_DOMAINS = ["example.com", "testcorp.io", "demo-company.net"]
FAKE_IPS = ["93.184.216.34", "8.8.8.8", "1.1.1.1", "104.21.50.100"]

FAKE_PLATFORMS = [
    "github",
    "twitter",
    "instagram",
    "linkedin",
    "reddit",
    "youtube",
    "tiktok",
    "pinterest",
    "stackoverflow",
]

FAKE_BREACH_NAMES = [
    "LinkedIn",
    "Adobe",
    "RockYou2021",
    "Facebook",
    "Dropbox",
    "MySpace",
    "Twitter",
    "LastFM",
    "Tumblr",
    "Yahoo",
]


def random_date(start_year: int = 2010, end_year: int = 2024) -> str:
    start = datetime(start_year, 1, 1)
    end = datetime(end_year, 12, 31)
    delta = end - start
    random_days = random.randint(0, delta.days)
    return (start + timedelta(days=random_days)).strftime("%Y-%m-%d")


def make_email_results(target: str) -> dict:
    return {
        "email_validator": {
            "success": True,
            "findings_count": 1,
            "data": {
                "email": target,
                "is_valid": True,
                "mx_records": [f"mail.{target.split('@')[1]}"],
                "spf_valid": random.choice([True, False]),
                "dmarc_valid": random.choice([True, False]),
                "is_disposable": False,
                "domain": target.split("@")[1],
            },
        },
        "hibp_breach_checker": {
            "success": True,
            "findings_count": random.randint(0, 5),
            "data": {
                "email": target,
                "total_breaches": random.randint(0, 8),
                "total_pastes": random.randint(0, 3),
                "breaches": [
                    {
                        "Name": random.choice(FAKE_BREACH_NAMES),
                        "BreachDate": random_date(),
                        "PwnCount": random.randint(100_000, 500_000_000),
                        "DataClasses": random.sample(
                            ["Email addresses", "Passwords", "Phone numbers", "Usernames"],
                            k=random.randint(1, 3),
                        ),
                    }
                    for _ in range(random.randint(0, 4))
                ],
            },
        },
        "email_permutator": {
            "success": True,
            "findings_count": 8,
            "data": {
                "target_name": target.split("@")[0].replace(".", " "),
                "domain": target.split("@")[1],
                "permutations": [
                    f"{target.split('@')[0]}@{target.split('@')[1]}",
                    f"{target.split('@')[0].replace('.', '')}@{target.split('@')[1]}",
                ],
            },
        },
    }


def make_username_results(username: str) -> dict:
    platforms = random.sample(FAKE_PLATFORMS, k=random.randint(3, 8))
    return {
        "social_checker": {
            "success": True,
            "findings_count": len(platforms),
            "data": {
                "username": username,
                "platforms": platforms,
                "platform_count": len(platforms),
                "github": {
                    "found": "github" in platforms,
                    "url": f"https://github.com/{username}",
                    "name": random.choice(FAKE_NAMES),
                    "public_repos": random.randint(0, 100),
                    "followers": random.randint(0, 5000),
                    "bio": "Software developer and open source contributor",
                }
                if "github" in platforms
                else None,
                "twitter": {
                    "found": "twitter" in platforms,
                    "url": f"https://twitter.com/{username}",
                    "followers": random.randint(10, 10000),
                }
                if "twitter" in platforms
                else None,
            },
        },
        "sherlock_wrapper": {
            "success": True,
            "findings_count": len(platforms),
            "data": {
                "username": username,
                "found_on": [
                    {
                        "site": p.title(),
                        "url": f"https://www.{p}.com/{username}",
                        "status": "Claimed",
                    }
                    for p in platforms
                ],
                "sites_checked": 400,
                "sites_found": len(platforms),
            },
        },
    }


def make_domain_results(domain: str) -> dict:
    subdomains = [f"www.{domain}", f"mail.{domain}", f"api.{domain}", f"app.{domain}"]
    return {
        "dns_recon": {
            "success": True,
            "findings_count": 5,
            "data": {
                "domain": domain,
                "a_records": [random.choice(FAKE_IPS)],
                "mx_records": [f"mail.{domain}"],
                "ns_records": ["ns1.example.com", "ns2.example.com"],
                "txt_records": [f"v=spf1 include:{domain} ~all"],
                "cname_records": {},
            },
        },
        "subdomain_enum": {
            "success": True,
            "findings_count": len(subdomains),
            "data": {
                "domain": domain,
                "subdomains": subdomains,
                "total_found": len(subdomains),
                "sources": {"crt_sh": len(subdomains) - 1, "bruteforce": 1},
            },
        },
        "certificate_search": {
            "success": True,
            "findings_count": len(subdomains),
            "data": {
                "domain": domain,
                "certificates": [
                    {
                        "name_value": sub,
                        "issuer_name": random.choice(["Let's Encrypt", "DigiCert", "Sectigo"]),
                        "not_before": random_date(2022, 2024),
                        "not_after": random_date(2024, 2026),
                    }
                    for sub in subdomains
                ],
            },
        },
    }


def make_ip_results(ip: str) -> dict:
    return {
        "ip_lookup": {
            "success": True,
            "findings_count": 1,
            "data": {
                "ip": ip,
                "country": random.choice(["United States", "Germany", "Netherlands", "UK"]),
                "city": random.choice(["New York", "Frankfurt", "Amsterdam", "London"]),
                "org": f"AS{random.randint(1000, 99999)} Example ISP",
                "abuse_score": random.randint(0, 30),
                "is_vpn": random.choice([True, False]),
                "is_tor": False,
                "open_ports": random.sample([22, 80, 443, 8080, 3306], k=random.randint(1, 3)),
            },
        },
        "geolocation": {
            "success": True,
            "findings_count": 1,
            "data": {
                "ip": ip,
                "geolocation": {
                    "country": "United States",
                    "country_code": "US",
                    "region": "California",
                    "city": "San Francisco",
                    "latitude": 37.7749,
                    "longitude": -122.4194,
                    "timezone": "America/Los_Angeles",
                },
                "asn": {"asn": f"AS{random.randint(1000, 99999)}", "org": "Example Corp"},
                "provider": "ip-api.com",
            },
        },
    }


def make_risk_assessment(module_results: dict) -> tuple[float, str]:
    breach_count = 0
    for r in module_results.values():
        if isinstance(r, dict) and isinstance(r.get("data"), dict):
            breach_count += r["data"].get("total_breaches", 0)

    score = min(10.0, breach_count * 0.8 + random.uniform(1, 4))
    if score >= 8:
        level = "critical"
    elif score >= 6:
        level = "high"
    elif score >= 4:
        level = "medium"
    else:
        level = "low"
    return round(score, 1), level


async def seed_scan(
    target: str,
    target_type: str,
    data_dir: Path,
) -> str:
    """Create a synthetic scan result on disk."""
    from app.engine.session import generate_request_id

    request_id = generate_request_id(target)
    scan_dir = data_dir / "requests" / request_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "raw_data").mkdir(exist_ok=True)
    (scan_dir / "reports").mkdir(exist_ok=True)

    # Generate module results
    if target_type == "email":
        module_results = make_email_results(target)
    elif target_type == "username":
        module_results = make_username_results(target)
    elif target_type == "domain":
        module_results = make_domain_results(target)
    elif target_type == "ip":
        module_results = make_ip_results(target)
    else:
        module_results = {}

    # Write per-module JSON files
    for module_name, result in module_results.items():
        with open(scan_dir / "raw_data" / f"{module_name}.json", "w") as f:
            json.dump(result, f, indent=2)

    risk_score, risk_level = make_risk_assessment(module_results)

    # Write metadata
    metadata = {
        "request_id": request_id,
        "target": target,
        "target_type": target_type,
        "status": "completed",
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": datetime.utcnow().isoformat(),
        "scan_duration_seconds": random.uniform(30, 300),
        "total_findings": sum(
            r.get("findings_count", 0) for r in module_results.values() if isinstance(r, dict)
        ),
        "modules_run": len(module_results),
        "modules_failed": 0,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }

    with open(scan_dir / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"  ✓ Created scan {request_id} for {target} (risk: {risk_level} {risk_score}/10)")
    return request_id


async def seed_sqlite(request_ids: list[str], data_dir: Path) -> None:
    """Register seeded scans in the SQLite cache."""
    try:
        from app.database.sqlite_cache import SQLiteCache

        db_path = data_dir / "cache" / "god_eye.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        cache = SQLiteCache(db_path=db_path)
        await cache.initialize()

        for rid in request_ids:
            meta_file = data_dir / "requests" / rid / "metadata.json"
            if meta_file.exists():
                with open(meta_file) as f:
                    meta = json.load(f)
                await cache.save_scan(meta)

        await cache.close()
        print(f"  ✓ Registered {len(request_ids)} scans in SQLite cache")
    except Exception as e:
        print(f"  ! SQLite registration failed: {e}")


async def main_async(args) -> None:
    data_dir = project_root / "data"

    if args.clear:
        import shutil

        requests_dir = data_dir / "requests"
        if requests_dir.exists():
            shutil.rmtree(requests_dir)
            print(f"Cleared {requests_dir}")
        return

    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "requests").mkdir(exist_ok=True)

    target_type = args.target_type
    count = args.count

    print(f"\nSeeding {count} synthetic {target_type} scan(s)...\n")

    targets = {
        "email": FAKE_EMAILS,
        "username": FAKE_USERNAMES,
        "domain": FAKE_DOMAINS,
        "ip": FAKE_IPS,
    }.get(target_type, FAKE_EMAILS)

    request_ids = []
    for i in range(count):
        target = targets[i % len(targets)]
        rid = await seed_scan(target, target_type, data_dir)
        request_ids.append(rid)

    print()
    await seed_sqlite(request_ids, data_dir)

    print("\nDone! View results:")
    print("  god-eye list")
    print(f"  god-eye view {request_ids[0]}")
    print("  uvicorn app.main:app --reload  # then visit /docs")


def main():
    parser = argparse.ArgumentParser(description="Seed GOD_EYE with synthetic test data")
    parser.add_argument(
        "--target-type",
        choices=["email", "username", "domain", "ip"],
        default="email",
        help="Type of targets to seed (default: email)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=3,
        help="Number of synthetic scans to create (default: 3)",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear all existing scan data",
    )
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
