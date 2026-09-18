#!/usr/bin/env python3
"""Analyze raw scan results: presence rates, misconfigurations, scores, tests.

Reads results/raw_results.csv, judges each of the six key headers
(present? correct? misconfigured?), computes a per-site score, produces
per-group statistics, chi-square tests across categories, and evaluates
hypotheses H1-H3.

Usage:
    python scanner/analyze.py            # writes results/analysis.json
    python scanner/analyze.py --print    # also print tables to stdout
"""

import argparse
import csv
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "results" / "raw_results.csv"
OUT = ROOT / "results" / "analysis.json"

SIX = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

GOOD_REFERRER = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}
GOOD_XCTO = {"nosniff"}
GOOD_XFO = {"deny", "sameorigin"}

HSTS_MIN_MAXAGE = 31536000  # 1 year, per OWASP recommendation

WEAK_REFERRER = {"unsafe-url", ""}


def classify_error(error: str) -> str:
    """Map a scanner error string to a coarse failure mode."""
    e = (error or "").lower()
    if not e:
        return ""
    if "nameresolutionerror" in e or "name or service not known" in e or "nodename nor servname" in e:
        return "dns"
    if "ssl" in e or "certificate" in e:
        return "ssl"
    if "timeout" in e or "timed out" in e:
        return "timeout"
    if "connection refused" in e or "connectionreset" in e or "connection aborted" in e:
        return "refused"
    if "toomanyredirects" in e:
        return "redirects"
    return "other"


def chi2_contingency_2xk(table: list[list[int]]) -> tuple[float, float]:
    """Chi-square test of independence for a 2 x k table (scipy-free)."""
    rows = len(table)
    cols = len(table[0])
    grand = sum(sum(r) for r in table)
    if grand == 0:
        return 0.0, 1.0
    row_sums = [sum(r) for r in table]
    col_sums = [sum(table[r][c] for r in range(rows)) for c in range(cols)]
    expected = [
        [row_sums[r] * col_sums[c] / grand for c in range(cols)] for r in range(rows)
    ]
    chi2 = 0.0
    for r in range(rows):
        for c in range(cols):
            if expected[r][c] > 0:
                chi2 += (table[r][c] - expected[r][c]) ** 2 / expected[r][c]
    dof = (rows - 1) * (cols - 1)
    # p-value from chi-square survival function via regularized gamma
    p = chi2_sf(chi2, dof)
    return chi2, p


def chi2_sf(x: float, k: int) -> float:
    """Survival function of chi-square with k dof (upper tail)."""
    return math.erfc((x / 2) ** 0.5 - (k / 2) ** 0.5) if k == 1 else _chi2_upper(x, k)


def _chi2_upper(x: float, k: int) -> float:
    """Wilson-Hilferty approximation for chi-square upper tail."""
    if x <= 0:
        return 1.0
    z = ((x / k) ** (1 / 3) - (1 - 2 / (9 * k))) / math.sqrt(2 / (9 * k))
    return 0.5 * math.erfc(z / math.sqrt(2))


def judge(header: str, value: str) -> str:
    """Classify one header value as 'ok', 'weak', or 'missing'."""
    if not value:
        return "missing"
    v = value.strip().lower()

    if header == "Content-Security-Policy":
        if "unsafe-inline" in v and "frame-ancestors" not in v:
            return "weak"
        if "unsafe-eval" in v:
            return "weak"
        if not v or v in {"report-only"}:
            return "missing"
        return "ok"
    if header == "Strict-Transport-Security":
        m = re.search(r"max-age\s*=\s*(\d+)", v)
        if not m:
            return "weak"
        maxage = int(m.group(1))
        if maxage < HSTS_MIN_MAXAGE:
            return "weak"
        return "ok"
    if header == "X-Frame-Options":
        val = v.split("|")[0].strip().strip('"')
        if val in GOOD_XFO:
            return "ok"
        if "allow-from" in val or val == "":
            return "weak"
        return "weak"
    if header == "X-Content-Type-Options":
        val = v.split("|")[0].strip()
        return "ok" if val.lower() in GOOD_XCTO else "weak"
    if header == "Referrer-Policy":
        val = v.split(",")[0].strip().lower()
        if val in GOOD_REFERRER:
            return "ok"
        if val in WEAK_REFERRER or "unsafe-url" in val:
            return "weak"
        return "weak"
    if header == "Permissions-Policy":
        # presence with any structured value counts as ok
        return "ok" if len(v) >= 3 else "weak"
    return "ok"


def verdict_counts(values: list[str]) -> Counter:
    return Counter(judge("Generic", "") if False else judge_h(h, v) for h, v in values)


def judge_h(header: str, value: str) -> str:
    return judge(header, value)


def site_score(row: dict) -> tuple[int, dict[str, str]]:
    """0-100: ok=full credit (100/6 each), weak=half, missing=0."""
    verdicts = {}
    points = 0.0
    for h in SIX:
        v = row.get(f"header_{h}", "")
        verdict = judge(h, v)
        verdicts[h] = verdict
        if verdict == "ok":
            points += 100 / 6
        elif verdict == "weak":
            points += 50 / 6
    return round(points), verdicts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--print", dest="do_print", action="store_true")
    args = parser.parse_args()

    with RAW.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    reachable = [r for r in rows if not r["error"]]
    print(f"Loaded {len(rows)} results, {len(reachable)} reachable.")

    # ---- reachability failure classification ---------------------------
    failures_by_type: dict[str, dict] = {}
    for r in rows:
        if not r["error"]:
            continue
        mode = classify_error(r["error"])
        bucket = failures_by_type.setdefault(
            mode, {"count": 0, "sites": [], "by_region": {"mz": 0, "global": 0}}
        )
        bucket["count"] += 1
        bucket["sites"].append(r["name"])
        region = (r.get("region") or "unknown").strip()
        bucket["by_region"][region] = bucket["by_region"].get(region, 0) + 1

    # ---- per-header verdicts across reachable sites --------------------
    header_stats: dict[str, dict] = {}
    for h in SIX:
        verdicts = [judge(h, r.get(f"header_{h}", "")) for r in reachable]
        n = len(reachable) or 1
        header_stats[h] = {
            "ok": verdicts.count("ok"),
            "weak": verdicts.count("weak"),
            "missing": verdicts.count("missing"),
            "ok_pct": round(100 * verdicts.count("ok") / n, 1),
            "present_pct": round(100 * (n - verdicts.count("missing")) / n, 1),
        }

    # most commonly missing / weak
    ranked = sorted(header_stats.items(), key=lambda kv: kv[1]["ok_pct"])
    most_missing = ranked[0][0] if ranked else ""
    most_weak = sorted(header_stats.items(), key=lambda kv: kv[1]["weak"])[0][0]
    # header with lowest presence
    lowest_presence = sorted(header_stats.items(), key=lambda kv: kv[1]["present_pct"])[0][0]

    # ---- per-site scores ------------------------------------------------
    scores: list[int] = []
    site_verdicts: dict[str, list[str]] = {}
    for r in reachable:
        s, v = site_score(r)
        scores.append(s)
        site_verdicts[r["url"]] = [v[h] for h in SIX]

    avg_score = round(sum(scores) / len(scores), 1) if scores else 0

    # H1: majority missing >= 2 of six
    missing_counts = [sum(1 for v in vs if v == "missing") for vs in site_verdicts.values()]
    missing_two_plus = sum(1 for c in missing_counts if c >= 2)
    h1_pct = round(100 * missing_two_plus / len(reachable), 1) if reachable else 0

    # H3: most commonly missing or weak header
    combined_deficit = {
        h: header_stats[h]["weak"] + header_stats[h]["missing"] for h in SIX
    }
    h3_header = sorted(combined_deficit.items(), key=lambda kv: -kv[1])[0][0] if SIX else ""

    # ---- group stats -----------------------------------------------------
    def group_by(key: str) -> dict[str, list[dict]]:
        groups: dict[str, list[dict]] = defaultdict(list)
        for r in reachable:
            groups[(r.get(key) or "unknown").strip()].append(r)
        return groups

    group_stats: dict[str, dict] = {}
    for key in ("region", "category"):
        groups = group_by(key)
        stats = {}
        for gname, grp in sorted(groups.items()):
            gscores = [site_score(r)[0] for r in grp]
            per_header = {}
            for h in SIX:
                verd = [judge(h, r.get(f"header_{h}", "")) for r in grp]
                per_header[h] = {
                    "ok_pct": round(100 * verd.count("ok") / len(grp), 1),
                    "present_pct": round(100 * (len(grp) - verd.count("missing")) / len(grp), 1),
                }
            # H1 within this group
            miss2 = sum(
                1
                for r in grp
                if sum(1 for h in SIX if judge(h, r.get(f"header_{h}", "")) == "missing") >= 2
            )
            stats[gname] = {
                "n": len(grp),
                "avg_score": round(sum(gscores) / len(gscores), 1) if gscores else 0,
                "per_header": per_header,
                "missing_two_plus_pct": round(100 * miss2 / len(grp), 1),
            }
        group_stats[key] = stats

    # ---- chi-square: header ok vs not-ok across categories ---------------
    categories = sorted({(r.get("category") or "unknown").strip() for r in reachable})
    chi_tests = {}
    for h in SIX:
        table = []
        for cat in categories:
            grp = [r for r in reachable if (r.get("category") or "unknown").strip() == cat]
            ok = sum(1 for r in grp if judge(h, r.get(f"header_{h}", "")) == "ok")
            table.append([ok, len(grp) - ok])
        # need 2 x k with rows = ok/not-ok
        ok_row = [t[0] for t in table]
        notok_row = [t[1] for t in table]
        chi2, p = chi2_contingency_2xk([ok_row, notok_row])
        chi_tests[h] = {"chi2": round(chi2, 3), "p": round(p, 4), "dof": len(categories) - 1}

    # H2: finance+government vs others (pooled)
    def pooled_avg(cats: list[str]) -> float:
        grp = [r for r in reachable if (r.get("category") or "unknown").strip() in cats]
        return round(sum(site_score(r)[0] for r in grp) / len(grp), 1) if grp else 0.0

    h2_sec = pooled_avg(["finance", "government"])
    h2_other = pooled_avg(["education", "commercial"])
    h2_diff = round(h2_sec - h2_other, 1)

    analysis = {
        "total_scanned": len(rows),
        "reachable": len(reachable),
        "unreachable": len(rows) - len(reachable),
        "failures_by_type": failures_by_type,
        "avg_score": avg_score,
        "header_stats": header_stats,
        "most_missing": most_missing,
        "lowest_presence": lowest_presence,
        "most_weak": most_weak,
        "h1": {
            "statement": "Majority of sites missing >= 2 of six headers",
            "pct_missing_two_plus": h1_pct,
            "n_missing_two_plus": missing_two_plus,
            "supported": h1_pct > 50,
        },
        "h2": {
            "statement": "Finance+government score higher than education+commercial",
            "sector_avg": h2_sec,
            "other_avg": h2_other,
            "difference": h2_diff,
            "supported": h2_diff > 0,
        },
        "h3": {
            "statement": "CSP is the most commonly missing/weak header",
            "header": h3_header,
            "supported": h3_header == "Content-Security-Policy",
        },
        "group_stats": group_stats,
        "chi_square_tests": chi_tests,
        "site_scores": [
            {
                "name": r["name"],
                "url": r["url"],
                "category": r.get("category", ""),
                "region": r.get("region", ""),
                "score": site_score(r)[0],
                "verdicts": {h: site_verdicts[r["url"]][i] for i, h in enumerate(SIX)},
            }
            for r in reachable
        ],
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(analysis, indent=2), encoding="utf-8")
    print(f"Analysis -> {OUT}")

    if args.do_print:
        print(f"\nAverage score: {avg_score}/100")
        print(f"{'Header':32} {'ok%':>6} {'present%':>9} {'weak':>5} {'missing':>8}")
        for h in SIX:
            s = header_stats[h]
            print(
                f"{h:32} {s['ok_pct']:>6} {s['present_pct']:>9} "
                f"{s['weak']:>5} {s['missing']:>8}"
            )
        print(f"\nH1: {h1_pct}% of sites missing >=2 headers -> "
              f"{'SUPPORTED' if analysis['h1']['supported'] else 'NOT supported'}")
        print(f"H2: sector {h2_sec} vs other {h2_other} (diff {h2_diff}) -> "
              f"{'SUPPORTED' if analysis['h2']['supported'] else 'NOT supported'}")
        print(f"H3: most missing/weak = {h3_header} -> "
              f"{'SUPPORTED' if analysis['h3']['supported'] else 'NOT supported'}")


if __name__ == "__main__":
    main()
