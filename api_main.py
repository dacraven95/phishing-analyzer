from fastapi import FastAPI, UploadFile, File
import tempfile
import os

from phish_analyzer.core import run_analysis_capture_text  # adjust import to match your structure

app = FastAPI()

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
