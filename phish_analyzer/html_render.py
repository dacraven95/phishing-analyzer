"""Fail-closed, bounded rendering of untrusted email HTML for PDF previews.

The preview is intentionally *not* a faithful browser execution of the email:
active content, remote images, form controls, external styles, and user CSS
are removed before HTML reaches Chromium. Full findings are retained by core.py.
"""
from __future__ import annotations

import html
import os
import signal
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

MAX_HTML_BYTES = 2 * 1024 * 1024
MAX_SANITIZED_BYTES = 2 * 1024 * 1024
MAX_CAPTURE_WIDTH = 1200
MAX_CAPTURE_HEIGHT = 1600
MAX_RENDER_SECONDS = 20
MAX_PNG_BYTES = 8 * 1024 * 1024

# Pass only browser-runtime variables to the worker, never API_KEY or credentials.
WORKER_ENV_KEYS = frozenset({
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "PYTHONPATH",
    "PLAYWRIGHT_BROWSERS_PATH", "XDG_RUNTIME_DIR", "TMPDIR", "TMP",
    "TEMP", "LD_LIBRARY_PATH", "SSL_CERT_FILE", "SSL_CERT_DIR",
})

# Permit a modest amount of email formatting, not browser functionality.
SAFE_TAGS = frozenset({
    "a", "b", "blockquote", "br", "center", "code", "dd", "del", "div",
    "dl", "dt", "em", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i",
    "li", "ol", "p", "pre", "s", "small", "span", "strong", "sub", "sup",
    "table", "tbody", "td", "th", "thead", "tr", "u", "ul",
})
EMPTY_TAGS = frozenset({"br", "hr"})
# Suppress the content of active, invisible, or document-metadata elements.
BLOCKED_CONTENT = frozenset({
    "script", "style", "svg", "math", "iframe", "frameset",
    "object", "head", "title", "template", "canvas", "video",
    "audio", "picture", "noscript",
})
# HTML void elements cannot start a suppression scope.
DROP_VOID_TAGS = frozenset({"link", "meta", "base", "source", "embed", "frame"})


class HTMLRenderError(RuntimeError):
    """The optional visual HTML preview was safely skipped."""


class _SafeEmailHTML(HTMLParser):
    """Rebuild HTML from an allowlist; never retain URL-bearing attributes."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._result: list[str] = []
        self._open: list[tuple[str, str]] = []
        self._blocked: str | None = None
        self._blocked_depth = 0
        self._chars = 0
        self._image_alts = 0

    def _append(self, value: str) -> None:
        if self._chars >= MAX_SANITIZED_BYTES:
            return
        value = value[:MAX_SANITIZED_BYTES - self._chars]
        self._result.append(value)
        self._chars += len(value)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if self._blocked is not None:
            if tag == self._blocked:
                self._blocked_depth += 1
            return
        if tag in DROP_VOID_TAGS:
            return
        if tag in BLOCKED_CONTENT:
            self._blocked = tag
            self._blocked_depth = 1
            return
        if tag == "img":
            # No src is retained: even tracking pixels and data: images stay inert.
            if self._image_alts < 6:
                alt = next((value for name, value in attrs if name.lower() == "alt" and value), None)
                if alt:
                    self._append('<span class="image-placeholder">[Image: '
                                 + html.escape(alt[:100], quote=True) + ']</span>')
                    self._image_alts += 1
            return
        if tag not in SAFE_TAGS:
            return
        if tag == "a":
            # Anchors retain their visible text, but never href, ping, onclick, etc.
            opening, closing = '<span class="link-text">', "</span>"
        elif tag in {"td", "th"}:
            spans: list[str] = []
            for name, value in attrs:
                if name.lower() in {"colspan", "rowspan"} and value and value.isdecimal():
                    spans.append(f' {name.lower()}="{min(int(value[:5]), 20)}"')
            opening, closing = f"<{tag}{''.join(spans)}>", f"</{tag}>"
        else:
            opening, closing = f"<{tag}>", f"</{tag}>"
        self._append(opening)
        if tag not in EMPTY_TAGS:
            if len(self._open) < 256:
                self._open.append((tag, closing))
            else:
                self._append(closing)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() not in EMPTY_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self._blocked is not None:
            if tag == self._blocked:
                self._blocked_depth -= 1
                if self._blocked_depth == 0:
                    self._blocked = None
            return
        for idx in range(len(self._open) - 1, -1, -1):
            if self._open[idx][0] == tag:
                for _, closing in reversed(self._open[idx:]):
                    self._append(closing)
                del self._open[idx:]
                break

    def handle_data(self, data: str) -> None:
        if self._blocked is None:
            self._append(html.escape(data, quote=True))

    def result(self) -> str:
        for _, closing in reversed(self._open):
            self._append(closing)
        return "".join(self._result)


def sanitize_email_html(email_html: str) -> str:
    """Keep readable email text/tables; drop scripts, images, CSS and HTML URLs."""
    if not isinstance(email_html, str):
        raise HTMLRenderError("Expected email HTML as text")
    if len(email_html.encode("utf-8", errors="replace")) > MAX_HTML_BYTES:
        raise HTMLRenderError("HTML preview exceeds its input size limit")
    parser = _SafeEmailHTML()
    try:
        parser.feed(email_html)
        parser.close()
    except (AssertionError, ValueError, RecursionError) as exc:
        raise HTMLRenderError("Unable to safely parse email HTML") from exc
    return parser.result()


def _kill_renderer_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    else:
        # On Windows, terminate the worker and its spawned Chromium children.
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                       capture_output=True, check=False, timeout=4)
        process.kill()
    process.communicate()


def render_html_to_png(
    html_content: str,
    output_png_path: str,
    viewport_width: int = 900,
    viewport_height: int = 1200,
    full_page: bool = True,
) -> str:
    """Render a static, sanitized email preview in a bounded subprocess.

    This does not access the network. Chromium's OS sandbox is required;
    launch failure is intentional rather than silently disabling its sandbox.
    """
    sanitized = sanitize_email_html(html_content)
    data = sanitized.encode("utf-8")
    if len(data) > MAX_SANITIZED_BYTES:
        raise HTMLRenderError("Sanitized HTML preview exceeds its size limit")
    width = max(320, min(int(viewport_width), MAX_CAPTURE_WIDTH))
    height = max(240, min(int(viewport_height), MAX_CAPTURE_HEIGHT))
    output = Path(output_png_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-m", "phish_analyzer._html_render_worker",
               str(output), str(width), str(height), "1" if full_page else "0"]
    worker_env = {key: value for key, value in os.environ.items()
                  if key in WORKER_ENV_KEYS}
    try:
        proc = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=(os.name == "posix"),
            env=worker_env,
        )
    except OSError as exc:
        raise HTMLRenderError("Could not start isolated HTML renderer") from exc
    try:
        proc.communicate(data, timeout=MAX_RENDER_SECONDS)
    except subprocess.TimeoutExpired as exc:
        _kill_renderer_process_tree(proc)
        output.unlink(missing_ok=True)
        raise HTMLRenderError("HTML rendering exceeded its time budget") from exc
    if (proc.returncode != 0 or not output.is_file()
            or not 0 < output.stat().st_size <= MAX_PNG_BYTES):
        output.unlink(missing_ok=True)
        # Never include the renderer's stderr in API responses; it may contain
        # snippets of the submitted email or internal filesystem paths.
        raise HTMLRenderError(f"HTML renderer unavailable (exit code {proc.returncode})")
    return str(output)
