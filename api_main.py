"""HTTP entry point for the phishing analyzer."""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

from fastapi import Depends, FastAPI, File, Form, HTTPException, Security, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security.api_key import APIKeyHeader
from starlette.background import BackgroundTask

from phish_analyzer.core import run_analysis_and_pdf, run_analysis_structured

logger = logging.getLogger(__name__)
# MCP is opt-in and protected by independent bearer-token authentication.
# A mounted ASGI app does not inherit FastAPI's /analyze dependencies.
mcp_token = os.getenv("MCP_API_TOKEN", "")
if mcp_token:
    from phish_analyzer.mcp_server import create_mcp_server

    mcp_server = create_mcp_server(mcp_token)
    mcp_app = mcp_server.http_app(path="/")
    app = FastAPI(lifespan=mcp_app.lifespan)
    app.mount("/mcp", mcp_app)
else:
    app = FastAPI()


API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)
MAX_EMAIL_BYTES = 25 * 1024 * 1024
UPLOAD_CHUNK_BYTES = 1024 * 1024
# Bound concurrent expensive scans; requests may queue while slots are occupied.
analysis_slots = asyncio.Semaphore(2)


async def verify_api_key(key: str | None = Security(api_key_header)) -> None:
    """Fail closed if API authentication is accidentally left unconfigured."""
    configured_key = os.getenv("API_KEY")
    if not configured_key:
        raise HTTPException(status_code=503, detail="API authentication is not configured")
    if not key or not secrets.compare_digest(key, configured_key):
        raise HTTPException(status_code=403, detail="Invalid or missing API key")


# Same-origin /api proxy requests do not require CORS. Allow configured cross-
# origin callers only; never combine a wildcard with credentialed browser access.
allowed_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["POST"],
    allow_headers=[API_KEY_NAME, "Content-Type"],
)


@app.post("/analyze")
async def analyze_email(
    file: UploadFile = File(...),
    create_pdf: bool = Form(False),
    _: None = Depends(verify_api_key),
    show_mime: bool = Form(False),
):
    # FastAPI validates a missing multipart file before entering this function.
    filename = (file.filename or "uploaded.eml").replace("\\", "/")
    display_filename = Path(filename).name.replace("\r", "").replace("\n", "")[:128]
    extension = PureWindowsPath(display_filename).suffix.lower()
    if extension not in {".eml", ".txt"}:
        await file.close()
        raise HTTPException(status_code=400, detail="Only .eml and .txt files are supported")

    # The request owns this directory. Never share one global report.pdf.
    temporary: tempfile.TemporaryDirectory[str] | None = tempfile.TemporaryDirectory(prefix="phish-api-")
    try:
        temp_path = Path(temporary.name) / ("uploaded" + extension)
        total_bytes = 0
        with temp_path.open("wb") as handle:
            while chunk := await file.read(UPLOAD_CHUNK_BYTES):
                total_bytes += len(chunk)
                if total_bytes > MAX_EMAIL_BYTES:
                    raise HTTPException(status_code=413, detail="Email exceeds the 25 MiB analysis limit")
                handle.write(chunk)
        if total_bytes == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")

        async with analysis_slots:
            if create_pdf:
                pdf_path = Path(temporary.name) / "report.pdf"
                await asyncio.to_thread(
                    run_analysis_and_pdf,
                    str(temp_path), str(pdf_path), show_mime,
                    display_filename=display_filename,
                )
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
                # FileResponse streams AFTER the handler returns. Delayed cleanup
                # keeps the PDF available until Starlette finishes sending it.
                response = FileResponse(
                    path=str(pdf_path),
                    media_type="application/pdf",
                    filename=f"phish-report-{stamp}.pdf",
                    background=BackgroundTask(temporary.cleanup),
                )
                temporary = None
                return response

            result = await asyncio.to_thread(
                run_analysis_structured,
                str(temp_path),
                show_mime=show_mime,
                display_filename=display_filename,
            )
            # Keep the original "output" field for the existing web frontend.
            return JSONResponse(jsonable_encoder(result.to_api_dict()))

    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Phishing analysis failed")
        raise HTTPException(status_code=500, detail="Internal analysis error") from exc
    finally:
        await file.close()
        if temporary is not None:
            temporary.cleanup()
