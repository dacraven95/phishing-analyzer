from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics

import re

# ------------ Public API ------------

def generate_pdf_report(
    output_path: str,
    text_output: str,
    analysis_results: Optional[List[Dict[str, Any]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    email_body: str | None = None,
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

    # Draw header and summary
    y = height - margins["top"]
    y = _draw_header(c, width, margins, y, metadata)
    y -= 0.25 * inch
    y = _draw_summary_box(c, width, margins, y, analysis_results, metadata)

    # Draw email body block
    if email_body:
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


# ------------ Internal helpers ------------

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

    left = margins["left"] + 0.4 * inch
    right = width - margins["right"] - 0.4 * inch
    max_width = right - left

    heading_font = "Helvetica-Bold"
    body_font = "Helvetica"
    heading_size = 12
    body_size = 9
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
    c.setFont(heading_font, heading_size)
    c.drawString(left, text_y, "Email Body (rendered)")
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
    c.drawString(margins["left"], y, "Phish Analyzer Report")
    y -= 0.3 * inch

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
        c.drawString(text_x, text_y, "No findings recorded.")
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
