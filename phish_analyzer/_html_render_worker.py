"""Internal subprocess entry point. Never call directly with untrusted raw HTML."""
from __future__ import annotations

import sys
from html import escape

from playwright.sync_api import sync_playwright

MAX_HTML_BYTES = 2 * 1024 * 1024

CSP = (
    "default-src 'none'; script-src 'none'; object-src 'none'; "
    "img-src 'none'; media-src 'none'; font-src 'none'; "
    "style-src 'unsafe-inline'; connect-src 'none'; "
    "frame-src 'none'; child-src 'none'; worker-src 'none'; "
    "form-action 'none'; base-uri 'none'"
)

CSS = """
html, body { margin: 0; padding: 0; background: #ffffff; color: #26333a; }
body { font: 15px/1.48 Arial, Helvetica, sans-serif; }
.email-preview {
    box-sizing: border-box; width: 100%; max-height: 2200px; overflow: hidden;
    padding: 20px; overflow-wrap: anywhere; word-break: normal;
}
table { border-collapse: collapse; width: auto; max-width: 100%; }
td, th { padding: 6px 9px; border: 1px solid #dce3e6; vertical-align: top; }
p { margin: 0 0 12px; } blockquote { margin-left: 12px; padding-left: 12px;
    border-left: 3px solid #b2bec5; }
a, .link-text { text-decoration: underline; color: #17638a; }
.image-placeholder { color: #5c6970; font-style: italic; }
pre { white-space: pre-wrap; }
"""


def main() -> int:
    if len(sys.argv) != 5:
        return 2
    output, width_raw, height_raw, full_raw = sys.argv[1:]
    width, height = int(width_raw), int(height_raw)
    if not (320 <= width <= 1200 and 240 <= height <= 1600):
        return 2
    body = sys.stdin.buffer.read(MAX_HTML_BYTES + 1)
    if len(body) > MAX_HTML_BYTES:
        return 2
    sanitized_html = body.decode("utf-8", errors="replace")
    html_document = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        '<meta http-equiv="Content-Security-Policy" content="'
        + escape(CSP, quote=True)
        + '"><style>' + CSS + '</style></head><body><main class="email-preview">'
        + sanitized_html + "</main></body></html>"
    )
    with sync_playwright() as playwright:
        # Sandbox enabled, not the Playwright default; fail closed if unsupported.
        browser = playwright.chromium.launch(
            headless=True, chromium_sandbox=True, timeout=7000,
            args=["--disable-background-networking", "--disable-extensions", "--no-first-run"],
        )
        try:
            context = browser.new_context(
                viewport={"width": width, "height": height},
                device_scale_factor=1,
                java_script_enabled=False,
                service_workers="block",
                accept_downloads=False,
                offline=True,
                permissions=[],
                reduced_motion="reduce",
            )
            try:
                # Deny even navigation/subresources not prevented by the sanitizer or CSP.
                context.route("**/*", lambda route: route.abort())
                page = context.new_page()
                page.set_default_timeout(5000)
                page.set_content(html_document, wait_until="domcontentloaded", timeout=5000)
                page.screenshot(path=output, full_page=(full_raw == "1"),
                                animations="disabled", timeout=7000, scale="css")
            finally:
                context.close()
        finally:
            browser.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # Do not dump exception text with potentially sensitive email content.
        raise SystemExit(1)
