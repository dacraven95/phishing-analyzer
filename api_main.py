from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import tempfile
import os

from phish_analyzer.core import run_analysis_capture_text  # adjust import to match your structure

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
async def analyze_email(file: UploadFile = File(...)):
    # Read uploaded file contents into memory
    contents = await file.read()

    # Create a real temporary file, cross-platform
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
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
