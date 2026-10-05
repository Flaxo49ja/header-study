#!/usr/bin/env python3
"""Render proposal/PROPOSAL.md into the submission PDF.

Cover page: USTM logo + university/faculty headers, title, author block.
Body: numbered sections parsed from PROPOSAL.md, justified text, running
header and page numbers on every page after the cover.

Usage:  python3 build_pdf.py
Output: Anayo_Anyafulu_RM2026ii_Research_Proposal.pdf (next to this script)
"""
import re
import shutil
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    Image,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
)

ROOT = Path(__file__).resolve().parent
MD = ROOT / "PROPOSAL.md"
LOGO = ROOT / "assets" / "school_logo.jpg"
OUT = ROOT / "Anayo_Anyafulu_RM2026ii_Research_Proposal.pdf"

TITLE = (
    "An Automated Analysis of HTTP Security Header Implementation Across "
    "Popular Websites: Identifying Common Misconfigurations and Gaps in "
    "Web Security Posture"
)
COMPONENTS = (
    "Submission of the Proposal on Specific Study Theme: Outlines, "
    "Literature Review, Contextualization, Methods, Problem Statement, "
    "Research Question(s), Objectives, Problem Analysis, Hypothesis and "
    "Prototype"
)

# ---------------------------------------------------------------- styles ---
BODY = ParagraphStyle(
    "Body", fontName="Times-Roman", fontSize=11, leading=15.5,
    alignment=TA_JUSTIFY, spaceAfter=8,
)
BULLET = ParagraphStyle(
    "Bullet", parent=BODY, alignment=TA_LEFT, leftIndent=16,
    firstLineIndent=0, spaceAfter=4, bulletIndent=4,
)
H2 = ParagraphStyle(
    "H2", fontName="Times-Bold", fontSize=13, leading=16,
    spaceBefore=14, spaceAfter=7, textColor=colors.HexColor("#1a1a2e"),
)
REF = ParagraphStyle(
    "Ref", fontName="Times-Roman", fontSize=10, leading=13.5,
    alignment=TA_LEFT, leftIndent=18, firstLineIndent=-18, spaceAfter=5,
)
COVER_TITLE = ParagraphStyle(
    "CoverTitle", fontName="Times-Bold", fontSize=16, leading=21,
    alignment=TA_CENTER, spaceAfter=6,
)
COVER_SMALL = ParagraphStyle(
    "CoverSmall", fontName="Times-Roman", fontSize=11, leading=15,
    alignment=TA_CENTER, spaceAfter=2,
)
COVER_ITAL = ParagraphStyle(
    "CoverItal", fontName="Times-Italic", fontSize=9, leading=12.5,
    alignment=TA_CENTER, spaceAfter=2,
)

ACCENT = colors.HexColor("#1f3a5f")


def md_inline(text: str) -> str:
    """Convert the small subset of markdown used in PROPOSAL.md to RL markup."""
    text = text.replace("α", "alpha")  # WinAnsi fonts lack the Greek glyph
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"\*(.+?)\*", r"<i>\1</i>", text)
    return text


def parse_markdown(path: Path):
    """Yield ('h2', text) / ('p', text) / ('li', text) blocks, skipping the
    document title block (the PDF cover carries that information)."""
    blocks, in_body = [], False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.startswith("## "):
            in_body = True
            blocks.append(("h2", line[3:].strip()))
        elif in_body and line.startswith("- "):
            blocks.append(("li", line[2:].strip()))
        elif in_body:
            blocks.append(("p", line.strip()))
    return blocks


# ------------------------------------------------------------ page frame ---
def header_footer(canvas, doc):
    if doc.page == 1:
        return  # cover page stays clean
    canvas.saveState()
    w, _h = A4
    canvas.setFont("Times-Italic", 8.5)
    canvas.setFillColor(colors.HexColor("#555555"))
    canvas.drawString(
        18 * mm, A4[1] - 12 * mm,
        "RM_2026-ii — Research Proposal — Anayo Chibuike Anyafulu",
    )
    canvas.drawRightString(w - 18 * mm, A4[1] - 12 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(ACCENT)
    canvas.setLineWidth(0.6)
    canvas.line(18 * mm, A4[1] - 14 * mm, w - 18 * mm, A4[1] - 14 * mm)
    canvas.restoreState()


def build_cover(story):
    story.append(Spacer(1, 16 * mm))
    if LOGO.exists():
        story.append(Image(str(LOGO), width=32 * mm, height=31.5 * mm))
        story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        "UNIVERSIDADE SÃO TOMÁS DE MOÇAMBIQUE",
        ParagraphStyle("U", parent=COVER_SMALL, fontName="Times-Bold",
                       fontSize=15, leading=19),
    ))
    story.append(Paragraph("Faculty of Computer Science", COVER_SMALL))
    story.append(Spacer(1, 5 * mm))
    story.append(HRFlowable(width="70%", thickness=1.1, color=ACCENT))
    story.append(Spacer(1, 7 * mm))
    story.append(Paragraph(
        "RESEARCH PROPOSAL",
        ParagraphStyle("RP", parent=COVER_SMALL, fontName="Times-Bold",
                       fontSize=13, textColor=ACCENT),
    ))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(TITLE, COVER_TITLE))
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("Prepared by:", COVER_SMALL))
    story.append(Paragraph(
        "Anayo Chibuike Anyafulu",
        ParagraphStyle("A", parent=COVER_SMALL, fontName="Times-Bold",
                       fontSize=12.5),
    ))
    story.append(Paragraph("Third-Year Computer Science Student", COVER_SMALL))
    story.append(Spacer(1, 7 * mm))
    story.append(Paragraph("Course: Research Methodology (RM_2026-ii)", COVER_SMALL))
    story.append(Paragraph(COMPONENTS, COVER_ITAL))
    story.append(Spacer(1, 9 * mm))
    story.append(Paragraph("Maputo, Mozambique — September 2026", COVER_SMALL))
    story.append(PageBreak())


def main():
    if not LOGO.exists():
        LOGO.parent.mkdir(parents=True, exist_ok=True)
        src = Path.home() / "Downloads" / "Images" / "school logo.jpg"
        if src.exists():
            shutil.copyfile(src, LOGO)
            print(f"copied logo from {src}")
        else:
            print(f"warning: logo not found at {src}; building without it")

    doc = BaseDocTemplate(
        str(OUT), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=20 * mm, bottomMargin=20 * mm,
        title=TITLE, author="Anayo Chibuike Anyafulu",
        subject="Research Proposal — RM_2026-ii, Universidade São Tomás de Moçambique",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
    doc.addPageTemplates([PageTemplate(id="page", frames=[frame], onPage=header_footer)])

    story = []
    build_cover(story)
    for kind, text in parse_markdown(MD):
        if kind == "h2":
            story.append(Paragraph(md_inline(text), H2))
            story.append(HRFlowable(width="100%", thickness=0.5,
                                    color=ACCENT, spaceAfter=6))
        elif kind == "li":
            story.append(Paragraph(md_inline(text), BULLET, bulletText="•"))
        else:
            story.append(Paragraph(md_inline(text), BODY))

    doc.build(story)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
