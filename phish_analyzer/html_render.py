from __future__ import annotations

from pathlib import Path
from typing import Optional

from playwright.sync_api import sync_playwright
from playwright.async_api import async_playwright
from PIL import Image, ImageChops


def render_html_to_png(
    html: str,
    output_png_path: str,
    *,
    viewport_width: int = 900,
    viewport_height: int = 900,
    full_page: bool = True,
) -> str:
    """
    Renders HTML to a PNG screenshot using headless Chromium (Playwright).

    - html: HTML string (should be complete HTML; if it's a fragment, wrap it)
    - output_png_path: where to write PNG
    - base_url: optionally set to allow relative resources to resolve

    Returns the PNG path.
    """
    out_path = Path(output_png_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # If someone passes an HTML fragment, wrap it so it renders consistently.
    if "<html" not in html.lower():
        html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>{html}</body>
</html>"""

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": viewport_width, "height": viewport_height})

        # set_content keeps it local; no clickable links in the screenshot output
        page.set_content(html, wait_until="load")

        # Optional: add a little time for fonts/images to settle (common with email HTML)
        page.wait_for_timeout(250)

        page.screenshot(path=str(out_path), full_page=full_page)

        trim_whitespace(out_path)

        browser.close()

    return str(out_path)

async def render_html_to_png_async(
    html: str,
    output_png_path: str,
    *,
    viewport_width: int = 900,
    viewport_height: int = 1200,
    full_page: bool = True,
    base_url: Optional[str] = None,
) -> str:
    out_path = Path(output_png_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if "<html" not in html.lower():
        html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>{html}</body>
</html>"""

    async with async_playwright() as p:
        browser = await p.chromium.launch(args=["--no-sandbox"])
        page = await browser.new_page(viewport={"width": viewport_width, "height": viewport_height})

        # NOTE: no base_url kwarg in python set_content
        await page.set_content(html, wait_until="load")
        await page.wait_for_timeout(250)

        # best: screenshot just the body to reduce whitespace
        body = page.locator("body")
        await body.screenshot(path=str(out_path))
        # or: await page.screenshot(path=str(out_path), full_page=full_page)

        trim_whitespace(out_path)

        await browser.close()

    return str(out_path)

def trim_whitespace(png_path: str) -> None:
    img = Image.open(png_path).convert("RGB")
    bg = Image.new("RGB", img.size, (255, 255, 255))
    diff = ImageChops.difference(img, bg)
    bbox = diff.getbbox()
    if bbox:
        img.crop(bbox).save(png_path)