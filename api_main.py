from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

import tempfile
import os
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
async def analyze_email(file: UploadFile = File(...), create_pdf: bool = Form(False)):
    
    # Read uploaded file contents into memory
    contents = await file.read()

    # Create a real temporary file, cross-platform
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        if create_pdf:
            # Run your existing analyzer on the temp file
            os.makedirs("./reports", exist_ok=True)
            now = datetime.now()
            filename_timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
            pdf_path = f"./reports/phish-report.pdf"
            run_analysis_and_pdf(tmp_path,pdf_path)

            return FileResponse(
                path=pdf_path,
                filename=f"phish-report-{filename_timestamp}.pdf",
                media_type="application/pdf"
            )
        else:
            # Run your existing analyzer on the temp file
            text_output = run_analysis_capture_text(
                tmp_path,
                use_json=True,
                strip_ansi=True,  # or False if you want colors in API output
            )

    finally:
        # Clean up the temp file
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    return {"text_output": text_output}
