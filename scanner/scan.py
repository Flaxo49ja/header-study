#!/usr/bin/env python3
"""Automated HTTP security header scanner.

Fetches each site in sites/sites.csv over HTTPS and records the six key
security headers plus the raw header set for offline analysis.

Polite scanning: single GET per site, 10s timeout, 1 retry on transient
errors, custom User-Agent, small thread pool.

Usage:
    python scanner/scan.py                 # scan all sites
    python scanner/scan.py --limit 5       # scan first 5 sites (smoke test)
    python scanner/scan.py --sites file.csv
"""

import argparse
import csv
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SITES = ROOT / "sites" / "sites.csv"
DEFAULT_OUT = ROOT / "results" / "raw_results.csv"

HEADERS_OF_INTEREST = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    # legacy / supplementary, recorded for context
    "Content-Security-Policy-Report-Only",
    "X-XSS-Protection",
    "X-Frame-Options-Report-Only",
]

USER_AGENT = (
    "USTM-Research-Scanner/1.0 (academic study of HTTP security headers; "
    "contact: research student, Universidade Sao Tomas de Mocambique)"
)

print_lock = threading.Lock()


def make_session() -> requests.Session:
    """Session with sane retries for transient network errors only."""
    retry = Retry(
        total=1,  # one retry
        backoff_factor=0.5,
        status_forcelist=[429, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=8, pool_maxsize=8)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    return session


def load_sites(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as fh:
        return [
            {k: (v or "").strip() for k, v in row.items()}
            for row in csv.DictReader(fh)
            if (row.get("url") or "").strip()
        ]


def scan_site(session: requests.Session, site: dict) -> dict:
    """Fetch one site and return a result row. Never raises."""
    name = site.get("name") or site["url"]
    url = site["url"]
    row = {
        "name": name,
        "url": url,
        "category": site.get("category", ""),
        "region": site.get("region", ""),
        "status": "",
        "final_url": "",
        "redirected": "",
        "error": "",
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    for h in HEADERS_OF_INTEREST:
        row[f"header_{h}"] = ""

    try:
        resp = session.get(url, timeout=10, allow_redirects=True)
        row["status"] = resp.status_code
        row["final_url"] = resp.url
        row["redirected"] = "yes" if resp.url.rstrip("/") != url.rstrip("/") else "no"

        # headers can appear multiple times; join duplicates
        lower_map: dict[str, list[str]] = {}
        for key, value in resp.headers.items():
            lower_map.setdefault(key.lower(), []).append(value)
        for h in HEADERS_OF_INTEREST:
            values = lower_map.get(h.lower())
            if values:
                row[f"header_{h}"] = " | ".join(v.strip() for v in values)
    except requests.RequestException as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"[:200]

    with print_lock:
        marker = "OK " if not row["error"] else "ERR"
        print(f"[{marker}] {name} -> {row['status'] or row['error']}")
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan sites for security headers.")
    parser.add_argument("--sites", type=Path, default=DEFAULT_SITES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--limit", type=int, default=0, help="only scan first N sites")
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    sites = load_sites(args.sites)
    if args.limit:
        sites = sites[: args.limit]
    print(f"Scanning {len(sites)} sites with {args.workers} workers...\n")

    session = make_session()
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(scan_site, session, site) for site in sites]
        for fut in as_completed(futures):
            results.append(fut.result())

    # keep input order
    order = {(s.get("name"), s["url"]): i for i, s in enumerate(sites)}
    results.sort(key=lambda r: order.get((r["name"], r["url"]), 10**9))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(results[0].keys()) if results else []
    with args.out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    ok = sum(1 for r in results if not r["error"])
    print(f"\nDone: {ok}/{len(results)} fetched OK. Results -> {args.out}")


if __name__ == "__main__":
    main()
