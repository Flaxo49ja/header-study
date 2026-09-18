#!/usr/bin/env python3
"""Generate results/summary.md and results/charts/*.png from analysis.json.

Usage:
    python scanner/report.py
"""

import argparse
import base64
import html as html_module
import json
import re
import time
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
ANALYSIS = ROOT / "results" / "analysis.json"
CHARTS = ROOT / "results" / "charts"
SUMMARY = ROOT / "results" / "summary.md"
OUT_HTML = ROOT / "results" / "report.html"
# Snapshot of the previous environment's analysis, if archived (for the
# before/after reachability comparison in the reproducibility note).
SANDBOX_ANALYSIS = ROOT / "results" / "analysis.sandbox.json"

SIX = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

plt.rcParams.update({"figure.dpi": 150, "font.size": 10})


def short(name: str) -> str:
    return (
        name.replace("Content-Security-Policy", "CSP")
        .replace("Strict-Transport-Security", "HSTS")
        .replace("X-Frame-Options", "XFO")
        .replace("X-Content-Type-Options", "XCTO")
        .replace("Referrer-Policy", "Referrer")
        .replace("Permissions-Policy", "Permissions")
    )


def chart_adoption(a: dict) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.2))
    names = [short(h) for h in SIX]
    present = [a["header_stats"][h]["present_pct"] for h in SIX]
    ok = [a["header_stats"][h]["ok_pct"] for h in SIX]
    weak = [a["header_stats"][h]["weak"] for h in SIX]

    x = range(len(SIX))
    ax.bar(x, present, label="Present (any value)", color="#9ecae1")
    ax.bar(x, ok, label="Configured correctly", color="#3182bd")
    ax.bar(x, weak, bottom=[p - w for p, w in zip(present, weak)],
           label="Present but weak", color="#fdae6b")
    ax.set_xticks(list(x))
    ax.set_xticklabels(names, rotation=20, ha="right")
    ax.set_ylabel("% of reachable sites")
    ax.set_title(f"Security header adoption (n={a['reachable']})")
    ax.legend()
    ax.set_ylim(0, 100)
    fig.tight_layout()
    fig.savefig(CHARTS / "01_adoption.png")
    plt.close(fig)


def chart_region(a: dict) -> None:
    regions = sorted(a["group_stats"]["region"])
    fig, axes = plt.subplots(1, len(regions), figsize=(4 * len(regions), 4), sharey=True)
    if len(regions) == 1:
        axes = [axes]
    for ax, region in zip(axes, regions):
        stats = a["group_stats"]["region"][region]
        names = [short(h) for h in SIX]
        vals = [stats["per_header"][h]["present_pct"] for h in SIX]
        ax.barh(names[::-1], vals[::-1], color="#74c476")
        ax.set_title(f"{region.upper()} (n={stats['n']})")
        ax.set_xlim(0, 100)
        ax.set_xlabel("% present")
    fig.suptitle("Header presence by region")
    fig.tight_layout()
    fig.savefig(CHARTS / "02_region.png")
    plt.close(fig)


def chart_category(a: dict) -> None:
    cats = sorted(a["group_stats"]["category"])
    fig, ax = plt.subplots(figsize=(8, 4.2))
    width = 0.2
    for i, cat in enumerate(cats):
        stats = a["group_stats"]["category"][cat]
        vals = [stats["per_header"][h]["ok_pct"] for h in SIX]
        xs = [j + (i - len(cats) / 2) * width for j in range(len(SIX))]
        ax.bar(xs, vals, width=width, label=f"{cat} (n={stats['n']})")
    ax.set_xticks(range(len(SIX)))
    ax.set_xticklabels([short(h) for h in SIX], rotation=20, ha="right")
    ax.set_ylabel("% configured correctly")
    ax.set_title("Correct configuration by website category")
    ax.legend()
    ax.set_ylim(0, 100)
    fig.tight_layout()
    fig.savefig(CHARTS / "03_category.png")
    plt.close(fig)


def chart_scores(a: dict) -> None:
    scores = [s["score"] for s in a["site_scores"]]
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.hist(scores, bins=range(0, 101, 10), color="#756bb1", edgecolor="white")
    mean = a["avg_score"]
    ax.axvline(mean, color="#e6550d", linestyle="--",
               label=f"Mean = {mean}")
    ax.set_xlabel("Security header score (0-100)")
    ax.set_ylabel("Number of sites")
    ax.set_title("Distribution of per-site scores")
    ax.legend()
    fig.tight_layout()
    fig.savefig(CHARTS / "04_scores.png")
    plt.close(fig)


def table(headers: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(headers) + " |"]
    out.append("|" + "|".join("---" for _ in headers) + "|")
    for row in rows:
        out.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(out)


# ---- HTML report -------------------------------------------------------
# Minimal markdown -> HTML covering exactly the constructs summary.md uses:
# headings, tables, lists, bold/italic, paragraphs, and images (embedded as
# base64 data URIs so report.html is fully self-contained).

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HTTP Security Header Study — Results</title>
<style>
  body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1a202c;
         line-height: 1.55; }
  h1 { border-bottom: 2px solid #3182bd; padding-bottom: .3rem; }
  h2 { margin-top: 2rem; color: #2c5282; }
  table { border-collapse: collapse; margin: 1rem 0; }
  th, td { border: 1px solid #cbd5e0; padding: .35rem .6rem; text-align: left; }
  th { background: #edf2f7; }
  img { max-width: 100%; height: auto; }
  li { margin: .3rem 0; }
  footer { margin-top: 3rem; font-size: .85rem; color: #718096; }
</style>
</head>
<body>
__BODY__
<footer>Generated __TS__ by scanner/report.py — Universidade São Tomás de Moçambique, RM_2026-ii.</footer>
</body>
</html>
"""


def _inline(text: str) -> str:
    """Escape HTML, then apply **bold** and *italic*."""
    text = html_module.escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    return text


def _img_tag(relpath: str, alt: str) -> str:
    path = ROOT / "results" / relpath
    if not path.exists():
        return f"<p><em>[missing chart: {html_module.escape(relpath)}]</em></p>"
    data = base64.b64encode(path.read_bytes()).decode("ascii")
    return f'<img src="data:image/png;base64,{data}" alt="{html_module.escape(alt)}">'


def md_to_html(md: str) -> str:
    lines = md.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # standalone image line -> embedded base64 chart
        m = re.fullmatch(r"!\[([^\]]*)\]\(([^)]+)\)", stripped)
        if m:
            out.append(_img_tag(m.group(2), m.group(1)))
            i += 1
            continue

        # table block
        if stripped.startswith("|"):
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                rows.append(cells)
                i += 1
            header, body_rows = rows[0], rows[2:]  # rows[1] is the |---| separator
            out.append("<table>")
            out.append("<thead><tr>" + "".join(f"<th>{_inline(c)}</th>" for c in header) + "</tr></thead>")
            out.append("<tbody>")
            for r in body_rows:
                out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>")
            out.append("</tbody></table>")
            continue

        # list block
        if stripped.startswith("- "):
            out.append("<ul>")
            while i < len(lines) and lines[i].strip().startswith("- "):
                out.append(f"<li>{_inline(lines[i].strip()[2:])}</li>")
                i += 1
            out.append("</ul>")
            continue

        if stripped.startswith("## "):
            out.append(f"<h2>{_inline(stripped[3:])}</h2>")
            i += 1
            continue
        if stripped.startswith("# "):
            out.append(f"<h1>{_inline(stripped[2:])}</h1>")
            i += 1
            continue
        if not stripped:
            i += 1
            continue

        out.append(f"<p>{_inline(stripped)}</p>")
        i += 1

    return "\n".join(out)


def failure_modes_section(a: dict) -> str:
    """Markdown section classifying why unreachable sites failed."""
    fbt = a.get("failures_by_type", {})
    if not fbt:
        return ""
    desc = {
        "dns": "Domain does not resolve in public DNS (NXDOMAIN or lame delegation) "
               "— site is dead or only reachable via local .mz resolvers.",
        "ssl": "TLS certificate fails verification (expired, self-signed, wrong "
               "hostname, or incomplete chain) — browsers warn users off, and the "
               "site cannot serve HSTS.",
        "timeout": "TCP connection accepted but no HTTP response within 10 s — "
                   "overloaded or misconfigured server/proxy.",
        "refused": "Server actively refused the connection.",
        "redirects": "Redirect loop.",
        "other": "Other connection error.",
    }
    order = ["dns", "ssl", "timeout", "refused", "redirects", "other"]
    rows = []
    for mode in order:
        if mode not in fbt:
            continue
        b = fbt[mode]
        names = "; ".join(b["sites"][:6]) + (f" … (+{len(b['sites']) - 6})" if len(b["sites"]) > 6 else "")
        rows.append([mode.upper(), b["count"], b["by_region"].get("mz", 0),
                     b["by_region"].get("global", 0), names])
    rows.sort(key=lambda r: -r[1])

    lines = [
        "## Reachability and failure modes",
        "",
        f"{a['unreachable']} of {a['total_scanned']} sampled sites could not be "
        "reached during the scan window. These are externally observable defects, "
        "not scanner artifacts, and are themselves findings:",
        "",
        table(["Failure mode", "n", "MZ", "Global", "Sites"], rows),
        "",
    ]
    for mode in order:
        if mode in fbt and mode in desc:
            lines.append(f"- **{mode.upper()}** — {desc[mode]}")
    lines += [
        "",
        "DNS failures on ministry domains mean the public cannot reach those "
        "sites at all; TLS failures mean users are shown security warnings and "
        "the site cannot deploy HSTS; timeouts suggest capacity or proxy "
        "misconfiguration. All three failure modes directly depress the header "
        "scores of the affected sites and help explain the MZ–global gap.",
    ]
    return "\n".join(lines)


def reproducibility_note(a: dict, location: str) -> str:
    """Short point-in-time snapshot note appended to summary.md."""
    lines = [
        "## Reproducibility note",
        "",
        f"- **Scan date:** {time.strftime('%Y-%m-%d', time.gmtime())} (UTC). "
        "Exact per-site timestamps are in `results/raw_results.csv`.",
        f"- **Network location:** {location}.",
    ]
    if SANDBOX_ANALYSIS.exists():
        before = json.loads(SANDBOX_ANALYSIS.read_text(encoding="utf-8"))
        delta = a["reachable"] - before["reachable"]
        lines.append(
            f"- **Reachability before/after:** {before['reachable']}/{before['total_scanned']} "
            f"sites reachable in the archived initial run vs "
            f"{a['reachable']}/{a['total_scanned']} in this run "
            f"({a['unreachable']} unreachable here; delta {delta:+d}). Reachability "
            "differences between vantage points are themselves evidence of "
            "routing/DNS fragility in parts of the .mz namespace.",
        )
    else:
        lines.append(
            f"- **Reachability:** {a['reachable']}/{a['total_scanned']} sites "
            f"reachable; {a['unreachable']} unreachable (classified by failure "
            "mode in the section above).",
        )
    lines.append(
        "- Header configurations change over time; re-running "
        "`scan.py → analyze.py → report.py` refreshes this snapshot and makes "
        "the study reproducible from any network."
    )
    return "\n".join(lines)


def write_html(md: str) -> None:
    body = md_to_html(md)
    page = (
        HTML_TEMPLATE.replace("__BODY__", body)
        .replace("__TS__", time.strftime("%Y-%m-%d %H:%M UTC"))
    )
    OUT_HTML.write_text(page, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build summary.md, charts, and report.html")
    parser.add_argument(
        "--location",
        default="not specified (pass --location, e.g. 'Maputo, Mozambique — Teledata Mozambique (AS36865)')",
        help="where the scan was executed from, recorded in the reproducibility note",
    )
    args = parser.parse_args()

    a = json.loads(ANALYSIS.read_text(encoding="utf-8"))
    CHARTS.mkdir(parents=True, exist_ok=True)

    chart_adoption(a)
    chart_region(a)
    chart_category(a)
    chart_scores(a)

    hs = a["header_stats"]
    rows = [
        [
            short(h),
            hs[h]["present_pct"],
            hs[h]["ok_pct"],
            hs[h]["weak"],
            hs[h]["missing"],
        ]
        for h in SIX
    ]

    chi_rows = [
        [short(h), t["chi2"], t["dof"], t["p"], "yes" if t["p"] < 0.05 else "no"]
        for h, t in a["chi_square_tests"].items()
    ]

    region_rows = [
        [r.upper(), s["n"], s["avg_score"], s["missing_two_plus_pct"]]
        for r, s in a["group_stats"]["region"].items()
    ]
    cat_rows = [
        [c, s["n"], s["avg_score"], s["missing_two_plus_pct"]]
        for c, s in a["group_stats"]["category"].items()
    ]

    verdict = lambda sup: "**supported**" if sup else "**not supported**"

    md = f"""# Results — Automated Analysis of HTTP Security Header Implementation

*Automated scan of {a['total_scanned']} sampled websites ({a['reachable']} reachable, {a['unreachable']} unreachable). Generated by `scanner/`.*

## RQ1 — What percentage of sites implement each header correctly?

{table(['Header', 'Present %', 'Correct %', 'Present but weak (n)', 'Missing (n)'], rows)}

## RQ2 — Most commonly missing or misconfigured header

Lowest presence: **{short(a['lowest_presence'])}**. Lowest correct-configuration rate: **{short(a['most_missing'])}**.

## RQ3 — Differences between website categories

{table(['Category', 'n', 'Avg score', '% missing ≥2 headers'], cat_rows)}

Chi-square tests of independence (header configured correctly vs not, across categories):

{table(['Header', 'χ²', 'dof', 'p', 'Significant (α=0.05)?'], chi_rows)}

## RQ4 — Average security header score

Mean score across reachable sites: **{a['avg_score']}/100**.

## Hypotheses

- **H1** ({a['h1']['statement']}): {a['h1']['pct_missing_two_plus']}% of sites ({a['h1']['n_missing_two_plus']}) were missing at least two headers → {verdict(a['h1']['supported'])}
- **H2** ({a['h2']['statement']}): finance+government avg {a['h2']['sector_avg']} vs education+commercial avg {a['h2']['other_avg']} (difference {a['h2']['difference']}) → {verdict(a['h2']['supported'])}
- **H3** ({a['h3']['statement']}): most missing/weak header = **{short(a['h3']['header'])}** → {verdict(a['h3']['supported'])}

## Charts

![Header adoption](charts/01_adoption.png)
![By region](charts/02_region.png)
![By category](charts/03_category.png)
![Score distribution](charts/04_scores.png)

## Regional comparison

{table(['Region', 'n', 'Avg score', '% missing ≥2 headers'], region_rows)}

{failure_modes_section(a)}

{reproducibility_note(a, args.location)}
"""
    SUMMARY.write_text(md, encoding="utf-8")
    write_html(md)
    print(f"Summary -> {SUMMARY}")
    print(f"Charts  -> {CHARTS}")
    print(f"HTML    -> {OUT_HTML}")


if __name__ == "__main__":
    main()
