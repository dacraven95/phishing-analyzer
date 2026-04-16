from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Security, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security.api_key import APIKeyHeader

import tempfile
import os
import traceback
import asyncio
import secrets

from datetime import datetime

from phish_analyzer.core import run_analysis_capture_text, run_analysis_and_pdf  # adjust import to match your structure

app = FastAPI()

# API Stuff
API_KEY = os.getenv("API_KEY")
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def verify_api_key(key: str = Security(api_key_header)):
    # If no API_KEY is present in the env, skip auth (dev purposes)
    if not API_KEY:
        return
    if not key or not secrets.compare_digest(key, API_KEY):
        raise HTTPException(status_code=403, detail="Invalid or missing API key")

# Allow specific origins, or * for all
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # <--- or restrict to specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/analyze")
async def analyze_email(
    file: UploadFile = File(...),
    create_pdf: bool = Form(False),
    _: None = Depends(verify_api_key),
):
    # 1) Validate file presence
    if file is None:
        raise HTTPException(status_code=400, detail="File is required")

    # 2) Save upload to temp
    try:
        contents = await file.read()
        if not contents:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
            tmp.write(contents)
            tmp_path = tmp.name

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error handling upload: {e}")

    try:
        # 3) If PDF requested in the form field
        if create_pdf:
            pdf_path = os.path.join(os.getcwd(), "report.pdf")
            await asyncio.to_thread(run_analysis_and_pdf, tmp_path, pdf_path)

            return FileResponse(
                path=pdf_path,
                media_type="application/pdf",
                filename=f"phish-report-{datetime.now()}.pdf",
            )

        # 4) Otherwise just return text/JSON output
        text_output = run_analysis_capture_text(
            tmp_path,
            use_json=False,
            strip_ansi=True,
        )
        return JSONResponse({"output": text_output})

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()  # <-- watch this in your container logs / console
        raise HTTPException(status_code=500, detail=f"Internal analysis error: {e}")

    finally:
        # 5) Cleanup temp file
        try:
            os.remove(tmp_path)
        except Exception:
            pass