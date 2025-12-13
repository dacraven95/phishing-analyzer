from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

import tempfile
import os
import traceback
import asyncio

from datetime import datetime

from phish_analyzer.core import run_analysis_capture_text, run_analysis_and_pdf  # adjust import to match your structure

app = FastAPI()

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