"""
Responsible for generating the PDFs for reporting
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path
import tempfile

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics

from phish_analyzer.html_render import render_html_to_png

BASE_DIR = Path(__file__).resolve().parent
VERSION = None

# ------------ Public API ------------

def generate_pdf_report(
    output_path: str,
    text_output: str,
    analysis_results: Optional[List[Dict[str, Any]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    # email_body: str | None = None,
) -> None:
    """
    Generate a PDF report for a phishing analysis run.

    :param output_path: Path where the PDF should be written.
    :param text_output: The captured terminal-style output (string).
    :param analysis_results: Optional list of structured findings (dicts).
    :param metadata: Optional dict with extra info, e.g.:
        {
            "file_name": "sample.eml",
            "overall_verdict": "suspicious",
            "overall_score": 78,
            "analyzed_at": datetime(...),
        }
    """
    if metadata is None:
        metadata = {}
    if analysis_results is None:
        analysis_results = []

    c = canvas.Canvas(output_path, pagesize=letter)
    width, height = letter

    # Page layout config
    margins = {
        "left": 0.75 * inch,
        "right": 0.75 * inch,
        "top": 0.75 * inch,
        "bottom": 0.75 * inch,
    }

    # The dashboard already carries the file, time, verdict, and key evidence.
    # Start the detailed report directly after a compact section heading instead
    # of repeating the metadata and severity summary on the following page.
    # Preserve the original header/summary for legacy callers without risk data.
    assessment = metadata.get("risk_assessment")
    has_dashboard = isinstance(assessment, dict) and "score" in assessment
    y = height - margins["top"]
    if has_dashboard:
        _draw_risk_dashboard(c, width, height, margins, metadata, assessment)
        c.showPage()
        y = _draw_technical_header(c, width, margins, y)
    else:
        y = _draw_header(c, width, margins, y, metadata)
        y -= 0.25 * inch
        y = _draw_summary_box(c, width, margins, y, analysis_results, metadata)

    received_hops = (metadata or {}).get("received_hops") or []
    # Reverse list so we have "first -> last" hops
    received_hops = list(reversed(received_hops))
    y = _draw_mail_flow_graph(c, received_hops, width, height, margins, y)

    html_png_path = None

    email_body = metadata.get("email_body") or None

    # Draw email body block
    if email_body:

        if is_html(email_body):

            # Each report gets a private renderer scratch directory. Reusing
            # ./reports/email_render.png would cause concurrent PDF data races.
            with tempfile.TemporaryDirectory(prefix="phish-render-") as render_dir:
                try:
                    html_png_path = render_html_to_png(
                        email_body,
                        output_png_path=str(Path(render_dir) / "email_render.png"),
                        viewport_width=900,
                        viewport_height=1200,
                        full_page=True,
                    )
                    y -= 0.5 * inch
                    min_readable_img_h = 4.25 * inch
                    y = _ensure_space(c, y, min_readable_img_h, height, margins)
                    y = _draw_email_html_screenshot(
                        c,
                        png_path=html_png_path,
                        width=width,
                        height=height,
                        margins=margins,
                        start_y=y,
                    )
                except Exception:
                    # HTML preview is optional. If Chromium cannot launch securely,
                    # times out, or produces an invalid image, preserve the report.
                    # The email text and the full analysis still appear below.
                    y = _ensure_space(c, y, 0.4 * inch, height, margins)
                    c.setFillColor(colors.HexColor("#596974"))
                    c.setFont("Helvetica-Oblique", 9)
                    c.drawString(margins["left"], y,
                                 "HTML visual preview unavailable; email content follows as text.")
                    y -= 0.3 * inch


        # Space before email body block
        y -= 0.5 * inch
        y = _draw_email_body_block(
            c,
            email_body=email_body,
            width=width,
            height=height,
            margins=margins,
            start_y=y,
        )

    # Space before terminal block
    # y -= 0.5 * inch

    # Draw terminal-like block with the text_output
    _draw_terminal_block(
        c,
        width,
        height,
        margins,
        start_y=y,
        text_output=text_output,
    )

    c.save()


def _draw_technical_header(
    c: canvas.Canvas,
    width: float,
    margins: Dict[str, float],
    y: float,
) -> float:
    """Start the details section without duplicating first-page metadata."""
    c.setFillColor(colors.HexColor("#172A35"))
    c.setFont("Helvetica-Bold", 16)
    c.drawString(margins["left"], y, "Technical details")
    y -= 0.18 * inch
    c.setStrokeColor(colors.HexColor("#E8EEF0"))
    c.setLineWidth(0.7)
    c.line(margins["left"], y, width - margins["right"], y)
    return y - 0.16 * inch


# ------------ Unified risk overview ------------


def _dashboard_color(score: int):
    if score >= 75:
        return colors.HexColor("#B42332")
    if score >= 50:
        return colors.HexColor("#C24535")
    if score >= 25:
        return colors.HexColor("#AA6B18")
    return colors.HexColor("#147D62")


def _fit_label(text: str, width: float, font: str, size: float) -> str:
    """Truncate untrusted long content rather than overflow the report page."""
    text = " ".join(str(text).split()).encode("latin-1", "replace").decode("latin-1")
    if pdfmetrics.stringWidth(text, font, size) <= width:
        return text
    while text and pdfmetrics.stringWidth(text + "...", font, size) > width:
        text = text[:-1]
    return text.rstrip() + "..."


def _draw_risk_dashboard(
    c: canvas.Canvas, width: float, height: float, margins: Dict[str, float],
    metadata: Dict[str, Any], risk: Dict[str, Any],
) -> None:
    """Visually stable first page backed by the same score as CLI/SQLite/JSON."""
    left, right = margins["left"], width - margins["right"]
    content_w = right - left
    score = max(0, min(100, int(risk.get("score", 0))))
    verdict = str(risk.get("verdict") or "UNDETERMINED").upper()
    accent = _dashboard_color(score)
    ink = colors.HexColor("#172A35")
    muted = colors.HexColor("#596974")
    light = colors.HexColor("#E8EEF0")
    teal = colors.HexColor("#127D70")
    y = height - margins["top"]

    c.setFont("Helvetica-Bold", 10)
    c.setFillColor(teal)
    c.drawString(left, y, "PHISH ANALYZER")
    c.setFont("Helvetica-Bold", 24)
    c.setFillColor(ink)
    y -= 33
    # c.drawString(left, y, "Unified risk assessment")
    # y -= 23
    c.drawString(margins["left"], y, f"Phish Analyzer Report v{get_version()}")
    y -= 23
    c.setFont("Helvetica", 9)
    c.setFillColor(muted)
    c.drawString(left, y, _fit_label(
        f"File: {Path(str(metadata.get('file_name', 'Unknown'))).name}", content_w, "Helvetica", 9))
    y -= 15
    stamp = metadata.get("analyzed_at")
    when = stamp.strftime("%Y-%m-%d %H:%M") if isinstance(stamp, datetime) else str(stamp or "")
    c.drawString(left, y, f"Analyzed: {when}   |   Method: {risk.get('method', 'heuristic')}")
    y -= 19

    # Main score panel
    card_h = 114
    c.setFillColor(colors.HexColor("#F3F8F7"))
    c.setStrokeColor(colors.HexColor("#DFEAE7"))
    c.roundRect(left, y-card_h, content_w, card_h, 10, fill=1, stroke=1)
    c.setFillColor(ink)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(left + 20, y - 26, "OVERALL RISK")
    c.setFillColor(accent)
    c.setFont("Helvetica-Bold", 34)
    c.drawString(left + 20, y - 71, str(score))
    c.setFont("Helvetica", 13)
    c.setFillColor(muted)
    c.drawString(left + 68, y - 68, "/ 100")
    c.setFont("Helvetica-Bold", 13)
    c.setFillColor(accent)
    c.drawRightString(right - 21, y - 43, verdict)
    c.setFillColor(muted)
    c.setFont("Helvetica", 9)
    c.drawRightString(right - 21, y - 61, "Heuristic assessment")
    c.setFillColor(light)
    c.roundRect(left + 20, y - 98, content_w - 40, 8, 4, stroke=0, fill=1)
    if score:
        c.setFillColor(accent)
        c.roundRect(left + 20, y - 98, (content_w - 40)*score/100, 8, 4, stroke=0, fill=1)
    y -= card_h + 26

    c.setFillColor(ink)
    c.setFont("Helvetica-Bold", 13)
    c.drawString(left, y, "Detection breakdown")
    y -= 22
    components = risk.get("components") or []
    for component in components[:5]:
        label = _fit_label(component.get("label", "Unknown"), 170, "Helvetica", 10)
        points = max(0, min(100, int(component.get("score", 0))))
        c.setFont("Helvetica", 10)
        c.setFillColor(ink)
        c.drawString(left, y, label)
        bar_x = left + 188
        bar_w = content_w - 232
        c.setFillColor(light)
        c.roundRect(bar_x, y-2, bar_w, 9, 4, stroke=0, fill=1)
        if points:
            c.setFillColor(_dashboard_color(points))
            c.roundRect(bar_x, y-2, bar_w*points/100, 9, 4, stroke=0, fill=1)
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(ink)
        c.drawRightString(right, y, f"{points}/100")
        y -= 29
    y -= 7

    c.setFillColor(ink)
    c.setFont("Helvetica-Bold", 13)
    c.drawString(left, y, "Key evidence")
    y -= 19
    evidence = risk.get("key_findings") or []
    if not evidence:
        evidence = ["No high-confidence suspicious indicators were recorded."]
    for item in evidence[:4]:
        c.setFillColor(accent)
        c.circle(left + 4, y + 3, 3, fill=1, stroke=0)
        c.setFont("Helvetica", 9)
        c.setFillColor(ink)
        c.drawString(left + 16, y, _fit_label(item, content_w - 20, "Helvetica", 9))
        y -= 20
    y -= 10

    warnings = risk.get("limitations") or []
    if warnings:
        c.setFillColor(ink)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(left, y, "Assessment limitations")
        y -= 15
        for warning in warnings[:2]:
            c.setFillColor(muted)
            c.setFont("Helvetica", 8)
            c.drawString(left, y, _fit_label(warning, content_w, "Helvetica", 8))
            y -= 12
    # Static guidance near footer; never conflate a low score with verified safety.
    c.setStrokeColor(light)
    c.line(left, margins["bottom"] + 27, right, margins["bottom"] + 27)
    c.setFillColor(muted)
    c.setFont("Helvetica", 8)
    c.drawString(left, margins["bottom"] + 13,
                 "Scores are investigative heuristics, not probabilities or definitive safety verdicts.")


# ------------ Internal helpers ------------

def _badge_style(level: str):
    level = (level or "").lower()
    if level in ("fail", "high", "bad", "error"):
        return colors.HexColor("#B91C1C"), colors.HexColor("#FEE2E2")  # red text, light red bg
    if level in ("warn", "warning", "medium", "suspicious"):
        return colors.HexColor("#92400E"), colors.HexColor("#FEF3C7")  # amber text, light amber bg
    if level in ("pass", "ok", "good", "success"):
        return colors.HexColor("#166534"), colors.HexColor("#DCFCE7")  # green text, light green bg
    return colors.HexColor("#1F2937"), colors.HexColor("#E5E7EB")      # gray default


def _draw_badge(c, x: float, y: float, text: str, level: str, *, font="Helvetica-Bold", size=8, pad_x=6, pad_y=3, radius=6):
    """
    Draw a pill badge whose top-left starts at (x, y). Returns (badge_w, badge_h).
    Note: y is the top edge of the badge box.
    """
    fg, bg = _badge_style(level)

    c.setFont(font, size)
    text_w = c.stringWidth(text, font, size)
    badge_w = text_w + pad_x * 2
    badge_h = size + pad_y * 2

    # background
    c.setFillColor(bg)
    c.setStrokeColor(bg)
    c.roundRect(x, y - badge_h, badge_w, badge_h, radius=radius, stroke=1, fill=1)

    # text
    c.setFillColor(fg)
    text_y = y - badge_h + (badge_h - size) / 2 + 1 # Font-aware vertical spacing in the badge
    c.drawString(x + pad_x, text_y, text)

    c.setFont("Helvetica", 9)

    return badge_w, badge_h

def _draw_mail_flow_graph(c, hops: list[dict], width: float, height: float, margins: dict, start_y: float) -> float:
    """
    Draws a simple vertical 'mail flow' diagram using Received hops.
    Returns the new y position after drawing.
    """
    if not hops:
        return start_y

    left = margins["left"]
    right = width - margins["right"]
    usable_w = right - left

    # Layout constants
    box_w = usable_w
    box_h = 0.55 * inch
    gap = 0.18 * inch
    arrow_h = 0.12 * inch
    pad_x = 0.14 * inch

    title_font = "Helvetica-Bold"
    title_size = 12
    text_font = "Helvetica"
    text_size = 9

    start_y -= 0.35 * inch

    y = start_y

    # Page break if needed
    needed = (title_size * 1.4) + (len(hops) * (box_h + gap + arrow_h)) + 0.3 * inch
    if y - needed < margins["bottom"] + 0.5 * inch:
        c.showPage()
        y = height - margins["top"] - 0.5 * inch

    # Title
    c.setFont(title_font, title_size)
    c.drawString(left, y, "Mail Flow (Received header path)")
    y -= 0.30 * inch

    # Draw each hop as a box + arrow to next
    c.setFont(text_font, text_size)

    for i, hop in enumerate(hops):
        frm = hop.get("from") or "unknown"
        by = hop.get("by") or "unknown"
        badges = hop.get("badges") or []

        # Box background + border
        c.setFillColor(colors.whitesmoke)
        c.setStrokeColor(colors.lightgrey)
        c.setLineWidth(1)
        c.roundRect(left, y - box_h, box_w, box_h, radius=6, stroke=1, fill=1)

        # Text inside box
        c.setFillColor(colors.black)
        line1 = f"{i+1}. from: {frm}"
        line2 = f"    by:   {by}"

        c.drawString(left + pad_x, y - 0.22 * inch, line1)
        c.drawString(left + pad_x, y - 0.40 * inch, line2)

        # Badges (right-aligned inside the box)
        badge_x_right = left + box_w - pad_x
        badge_top = y - 0.16 * inch  # near top of box
        badge_gap = 0.06 * inch

        # Draw from right to left so they stack neatly
        for b in reversed(badges):
            label = b.get("text", "").strip()
            level = b.get("level", "info")
            if not label:
                continue

            # measure badge width by drawing off-screen? easier: call draw then adjust based on returned width
            # We'll draw at a provisional x, then adjust:
            # Instead: estimate width using current font settings:
            # We'll just call _draw_badge with x=0 to get width? it would draw.
            # Better: compute width using stringWidth.
            c.setFont("Helvetica-Bold", 8)
            text_w = c.stringWidth(label, "Helvetica-Bold", 8)
            badge_w = text_w + 6 * 2  # pad_x*2 from helper default (6)
            x = badge_x_right - badge_w

            _draw_badge(c, x, badge_top, label, level)
            badge_x_right = x - badge_gap  # shift left for next badge

        # Arrow (except after last)
        y = y - box_h - gap
        if i < len(hops) - 1:
            mid_x = left + box_w / 2
            c.setStrokeColor(colors.grey)
            c.setLineWidth(1)
            c.line(mid_x, y, mid_x, y - arrow_h)

            # arrow head
            c.line(mid_x, y - arrow_h, mid_x - 4, y - arrow_h + 4)
            c.line(mid_x, y - arrow_h, mid_x + 4, y - arrow_h + 4)

            y -= arrow_h

    # spacing after block
    return y - 0.25 * inch

def is_html(email_body):
    if "<html" in email_body:
        return True
    else:
        return False

def _ensure_space(c, y, needed, height, margins, pad=0.5*inch):
    if y - needed < margins["bottom"] + pad:
        c.showPage()
        return height - margins["top"] - pad
    return y

def _draw_email_html_screenshot(c, png_path: str, width: float, height: float, margins: dict, start_y: float) -> float:
    """
    Draw the rendered HTML screenshot PNG into the PDF. Returns new Y position.
    """
    if not png_path:
        return start_y

    left = margins["left"]
    right = width - margins["right"]
    max_w = right - left

    # Heading
    heading_font = "Helvetica-Bold"
    heading_size = 12
    heading_gap = 0.3 * inch

    text_y = start_y

    c.setFont(heading_font, heading_size)
    c.setFillColor(colors.black)
    c.drawString(left, start_y, "Email Body (rendered as image)")

    text_y -= (heading_size * 1.2)      # line height for heading
    # text_y -= (0.12 * inch)             # extra breathing room

    # Reserve a reasonable height; you can tune this.
    available_h = (start_y - (margins["bottom"] + 0.5 * inch))
    max_h = min(6.5 * inch, available_h)
    pad = 0.10 * inch

    # Page break if not enough space
    if start_y - max_h < margins["bottom"] + 0.5 * inch:
        c.showPage()
        start_y = height - margins["top"] - 0.5 * inch

    img = ImageReader(png_path)
    iw, ih = img.getSize()

    # Scale to fit within max_w x max_h (preserve aspect)
    scale = min(max_w / iw, max_h / ih)
    draw_w = iw * scale
    draw_h = ih * scale

    frame_w = max_w
    frame_h = draw_h + pad*2

    frame_x = left
    frame_y = start_y - frame_h

    # ✅ background + border
    c.setFillColor(colors.whitesmoke)
    c.setStrokeColor(colors.lightgrey)
    c.setLineWidth(1)
    # c.rect(frame_x, frame_y, frame_w, frame_h, stroke=1, fill=1)

    # image inside frame
    x = frame_x + pad
    y = frame_y - 1.2
    c.drawImage(img, x, y, width=draw_w, height=draw_h, mask="auto")

    return y - 0.3 * inch

def _draw_email_body_block(
    c: canvas.Canvas,
    width: float,
    height: float,
    margins: Dict[str, float],
    start_y: float,
    email_body: str,
) -> None:
    """
    Draws the email body as a rendered text block after the summary and
    returns the new Y position to continue drawing from.
    """
    if not email_body:
        return start_y

    left = margins["left"]
    right = width - margins["right"]
    # left = margins["left"] + 0.4 * inch
    # right = width - margins["right"] - 0.4 * inch
    max_width = right - left

    heading_font = "Helvetica-Bold"
    body_font = "Helvetica"
    heading_size = 12
    body_size = 6
    line_height = body_size * 1.4
    heading_gap = 0.3 * inch

    text_y = start_y

    # Page break before heading if we're too low
    if text_y <= margins["bottom"] + 1.0 * inch:
        c.showPage()
        # if you have a page background/header function, call it here
        # _draw_page_frame(c, width, height, margins)
        text_y = height - margins["top"] - 0.5 * inch

    # Heading
    c.setFillColor(colors.black)
    c.setFont(heading_font, heading_size)
    c.drawString(left, text_y, "Email Body (plain text)")
    text_y -= heading_gap

    c.setFont(body_font, body_size)
    wrapped_lines = _wrap_text_lines(email_body, max_width, body_font, body_size)

    for line in wrapped_lines:
        if text_y <= margins["bottom"] + 0.5 * inch:
            # New page and reset Y if we run out of space
            c.showPage()
            # again, call your page frame/header if you have one:
            # _draw_page_frame(c, width, height, margins)
            c.setFont(body_font, body_size)
            text_y = height - margins["top"] - 0.5 * inch

        c.drawString(left, text_y, line)
        text_y -= line_height

    # Add a bit of space before whatever comes next
    text_y -= 0.3 * inch
    return text_y

# Regex to match ANSI color codes like \x1b[91m, \x1b[0m, etc.
ANSI_COLOR_RE = re.compile(r"\x1b\[(\d+)(?:;(\d+))?m")


def _ansi_color_for_code(code: str):
    """
    Map an ANSI SGR color code (like '91') to a ReportLab color.
    Adjust this mapping to match the colors you're actually using.
    """
    # Common codes:
    # 30–37: normal fg colors, 90–97: bright fg colors, 0: reset
    if code in ("0", "39"):
        # reset / default
        return colors.lawngreen  # default terminal green

    # Standard colors
    if code == "30":
        return colors.black
    if code == "31":
        return colors.red
    if code == "32":
        return colors.green
    if code == "33":
        return colors.yellow
    if code == "34":
        return colors.blue
    if code == "35":
        return colors.magenta
    if code == "36":
        return colors.cyan
    if code == "37":
        return colors.white

    # Bright colors
    if code == "90":
        return colors.darkgrey
    if code == "91":
        return colors.red
    if code == "92":
        return colors.lawngreen
    if code == "93":
        return colors.gold
    if code == "94":
        return colors.cornflower
    if code == "95":
        return colors.violet
    if code == "96":
        return colors.aquamarine
    if code == "97":
        return colors.whitesmoke

    # Fallback
    return colors.lawngreen

def _new_page_y(page_h, margins, pad=0.25*inch):
    return page_h - margins["top"] - pad

def _wrap_text_lines(text: str, max_width: float, font_name: str, font_size: float) -> list[str]:
    """
    Simple word-wrap: breaks a long text into lines that fit within max_width.
    """
    lines: list[str] = []
    for raw_line in text.splitlines():
        words = raw_line.split(" ")
        if not words:
            lines.append("")  # keep empty lines
            continue

        current = ""
        for word in words:
            candidate = word if not current else current + " " + word
            if pdfmetrics.stringWidth(candidate, font_name, font_size) <= max_width:
                current = candidate
            else:
                if current:
                    lines.append(current)
                # word itself may be longer than max_width; hard-break if needed
                while pdfmetrics.stringWidth(word, font_name, font_size) > max_width:
                    # rough split by character count
                    avg_char = pdfmetrics.stringWidth(word, font_name, font_size) / len(word)
                    max_chars = max(1, int(max_width / avg_char))
                    lines.append(word[:max_chars])
                    word = word[max_chars:]
                current = word
        lines.append(current)
    return lines

def _parse_ansi_spans(line: str):
    """
    Given a line containing ANSI color codes, return a list of:
        [(color, text), (color, text), ...]
    with the ANSI codes removed and colors resolved.

    Example:
        "normal \x1b[91mred\x1b[0m normal"
    becomes:
        [(default_color, "normal "),
         (red, "red"),
         (default_color, " normal")]
    """
    spans = []
    last_end = 0
    current_color = colors.lawngreen  # default terminal green

    for match in ANSI_COLOR_RE.finditer(line):
        start, end = match.span()

        # Text before this ANSI code uses current_color
        if start > last_end:
            text_segment = line[last_end:start]
            if text_segment:
                spans.append((current_color, text_segment))

        sgr1 = match.group(1)  # primary SGR code (e.g. "91")
        # sgr2 = match.group(2)  # secondary, if ever needed (e.g. bold+color)

        current_color = _ansi_color_for_code(sgr1)
        last_end = end

    # Remaining text after the last ANSI code
    if last_end < len(line):
        text_segment = line[last_end:]
        if text_segment:
            spans.append((current_color, text_segment))

    # If no spans at all (empty line), return one empty segment
    if not spans:
        spans.append((current_color, ""))

    return spans

def _draw_header(
    c: canvas.Canvas,
    width: float,
    margins: Dict[str, float],
    y: float,
    metadata: Dict[str, Any],
) -> float:
    """Draw report title + basic info at the top of the page."""

    analyzed_at = metadata.get("analyzed_at") or datetime.now()
    if isinstance(analyzed_at, datetime):
        analyzed_at_str = analyzed_at.strftime("%Y-%m-%d %H:%M:%S")
    else:
        analyzed_at_str = str(analyzed_at)

    file_name = metadata.get("file_name", "Unknown file")
    overall_verdict = metadata.get("overall_verdict", "N/A")
    overall_score = metadata.get("overall_score")

    # Title
    c.setFont("Helvetica-Bold", 20)
    c.setFillColor(colors.black)
    # c.drawString(margins["left"], y, f"Phish Analyzer Report v{get_version()}")
    # y -= 0.3 * inch

    # Meta line 1
    c.setFont("Helvetica", 10)
    c.setFillColor(colors.grey)
    c.drawString(
        margins["left"],
        y,
        f"Analyzed file: {file_name}",
    )
    y -= 0.2 * inch

    # Meta line 2
    c.drawString(
        margins["left"],
        y,
        f"Analyzed at: {analyzed_at_str}",
    )
    y -= 0.2 * inch

    # Meta line 3 (overall verdict / score)
    verdict_text = f"Overall verdict: {overall_verdict}"
    if overall_score is not None:
        verdict_text += f"  |  Score: {overall_score}"

    c.drawString(
        margins["left"],
        y,
        verdict_text,
    )
    y -= 0.1 * inch

    # Divider line
    c.setStrokeColor(colors.grey)
    c.setLineWidth(0.5)
    c.line(
        margins["left"],
        y,
        width - margins["right"],
        y,
    )
    y -= 0.1 * inch

    return y


def _summarize_by_severity(
    analysis_results: List[Dict[str, Any]]
) -> Dict[str, int]:
    """Count findings by severity."""
    counts: Dict[str, int] = {}
    for item in analysis_results:
        sev = (item.get("severity") or "").lower()
        if not sev:
            sev = "unknown"
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _draw_summary_box(
    c: canvas.Canvas,
    width: float,
    margins: Dict[str, float],
    y: float,
    analysis_results: List[Dict[str, Any]],
    metadata: Dict[str, Any],
) -> float:
    """
    Draw a simple summary box: counts by severity and maybe basic stats.
    Returns new y coordinate under the box.
    """
    box_top = y
    box_left = margins["left"]
    box_right = width - margins["right"]

    # Rough height; we'll adjust a bit based on actual lines
    box_height = 1.25 * inch
    box_bottom = y - box_height

    # Background
    c.setFillColor(colors.whitesmoke)
    c.setStrokeColor(colors.lightgrey)
    c.setLineWidth(0.5)
    c.roundRect(
        box_left,
        box_bottom,
        box_right - box_left,
        box_top - box_bottom,
        radius=6,
        stroke=1,
        fill=1,
    )

    # Title
    inner_margin = 0.15 * inch
    text_x = box_left + inner_margin
    text_y = box_top - inner_margin - 0.05 * inch

    c.setFont("Helvetica-Bold", 12)
    c.setFillColor(colors.black)
    c.drawString(text_x, text_y, "Summary")
    text_y -= 0.25 * inch

    # Severity counts
    counts = _summarize_by_severity(analysis_results)

    c.setFont("Helvetica", 9)
    if counts:
        for sev in sorted(counts.keys()):
            count = counts[sev]
            c.setFillColor(_severity_color(sev))
            c.drawString(text_x, text_y, f"{sev.title()}: {count}")
            text_y -= 0.18 * inch
    else:
        c.setFillColor(colors.grey)
        c.drawString(text_x, text_y, "No findings recorded. This feature is still under development.")
        text_y -= 0.18 * inch

    return box_bottom - 0.15 * inch


def _severity_color(severity: str):
    sev = (severity or "").lower()
    if sev == "critical":
        return colors.red
    if sev == "high":
        return colors.orange
    if sev == "medium":
        return colors.darkgoldenrod
    if sev == "low":
        return colors.darkgreen
    if sev == "info":
        return colors.grey
    return colors.black


def _draw_terminal_block(
    c: canvas.Canvas,
    width: float,
    height: float,
    margins: Dict[str, float],
    start_y: float,
    text_output: str,
) -> None:
    """
    Draw a terminal-like block containing the captured text_output.

    Monospaced font, dark background, light text.
    Parses ANSI color codes and maps them to PDF colors.
    Automatically handles page breaks if the output is long.
    """
    # Layout
    term_left = margins["left"]
    term_right = width - margins["right"]
    term_top = start_y
    term_bottom_margin = margins["bottom"]

    # Background panel on this page
    panel_height = term_top - term_bottom_margin
    c.setFillColor(colors.black)
    c.setStrokeColor(colors.black)
    c.roundRect(
        term_left,
        term_bottom_margin,
        term_right - term_left,
        panel_height,
        radius=6,
        stroke=1,
        fill=1,
    )

    # Text config
    font_name = "Courier"
    font_size = 8.5
    c.setFont(font_name, font_size)
    line_height = 10  # points
    text_y = term_top - 0.25 * inch
    text_x_start = term_left + 0.15 * inch

    lines = text_output.splitlines() if text_output else ["(no terminal output captured)"]

    for raw_line in lines:
        # If we've reached bottom, start a new page and redraw panel
        if text_y <= term_bottom_margin + 0.25 * inch:
            c.showPage()
            _draw_terminal_panel_background(c, width, height, margins)
            c.setFont(font_name, font_size)
            text_y = height - margins["top"] - 0.25 * inch

        line = raw_line  # no truncation here

        spans = _parse_ansi_spans(line)
        cursor_x = text_x_start

        for color_val, span_text in spans:
            if not span_text:
                continue

            # We may need to wrap this span across multiple lines
            remaining = span_text
            while remaining:
                # If current line is full, move to next line
                max_width = term_right - cursor_x - 0.15 * inch
                if max_width <= 0:
                    text_y -= line_height
                    cursor_x = text_x_start

                    # Page break if needed
                    if text_y <= term_bottom_margin + 0.25 * inch:
                        c.showPage()
                        _draw_terminal_panel_background(c, width, height, margins)
                        c.setFont(font_name, font_size)
                        text_y = height - margins["top"] - 0.25 * inch

                    max_width = term_right - cursor_x - 0.15 * inch

                span_width = c.stringWidth(remaining, font_name, font_size)

                if span_width <= max_width:
                    # Entire remaining span fits on this line
                    c.setFillColor(color_val)
                    c.drawString(cursor_x, text_y, remaining)
                    cursor_x += span_width
                    remaining = ""  # done with this span
                else:
                    # Need to split this span across lines
                    # Since we're using Courier (monospace), this estimate is fine
                    avg_char_width = span_width / len(remaining)
                    max_chars_fit = int(max_width / avg_char_width)
                    if max_chars_fit <= 0:
                        # Nothing fits; force line break and try again
                        text_y -= line_height
                        cursor_x = text_x_start

                        if text_y <= term_bottom_margin + 0.25 * inch:
                            c.showPage()
                            _draw_terminal_panel_background(c, width, height, margins)
                            c.setFont(font_name, font_size)
                            text_y = height - margins["top"] - 0.25 * inch

                        continue

                    part = remaining[:max_chars_fit]
                    remaining = remaining[max_chars_fit:]

                    c.setFillColor(color_val)
                    c.drawString(cursor_x, text_y, part)
                    # move to next line for the remainder
                    text_y -= line_height
                    cursor_x = text_x_start

                    # Page break if needed before drawing the next chunk
                    if text_y <= term_bottom_margin + 0.25 * inch:
                        c.showPage()
                        _draw_terminal_panel_background(c, width, height, margins)
                        c.setFont(font_name, font_size)
                        text_y = height - margins["top"] - 0.25 * inch

        # After finishing this logical line, move to the next PDF line
        text_y -= line_height


def _draw_terminal_panel_background(
    c: canvas.Canvas,
    width: float,
    height: float,
    margins: Dict[str, float],
) -> None:
    """Draw just the black terminal background panel for a new page."""
    term_left = margins["left"]
    term_right = width - margins["right"]
    term_top = height - margins["top"]
    term_bottom_margin = margins["bottom"]

    panel_height = term_top - term_bottom_margin

    c.setFillColor(colors.black)
    c.setStrokeColor(colors.black)
    c.roundRect(
        term_left,
        term_bottom_margin,
        term_right - term_left,
        panel_height,
        radius=6,
        stroke=1,
        fill=1,
    )


def get_version():
    global  VERSION
    if VERSION is None:
        version_file = BASE_DIR / 'config' / 'version.txt'
        try:
            with open(version_file, 'r') as vf:
                VERSION = vf.read().strip()
        except FileNotFoundError:
            VERSION = "unknown"
    return VERSION