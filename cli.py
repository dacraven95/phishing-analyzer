#!/usr/bin/env python3
import argparse
import os
import sys
from phish_analyzer.core import run_analysis, run_analysis_and_pdf
from datetime import datetime
from halo import Halo

def main():
    parser = argparse.ArgumentParser(...)
    parser.add_argument("-f", "--file", required=True, help="The email or header file needing to be anlyzed")
    parser.add_argument("-j", "--json", action="store_true", help="Output an analysis_results JSON object")
    parser.add_argument("--no-color", action="store_true", help="Do not color terminal output (NOT WORKING AT THE MOMENT)")
    parser.add_argument("-r","--report", action="store_true", help="Generate a PDF report instead of terminal output")
    parser.add_argument("-o","--output", type=str, help="Path to write the generated PDF report (CLI only)")
    parser.add_argument("-m", "--mime", action="store_true", help="Dump email MIME data on output")

    args = parser.parse_args()

    file_path = args.file

    ### Email file validation before running analysis
    # Checking if the file exists
    if not os.path.exists(file_path):
        print(f"[!] Error: File not found: '{file_path}'")
        sys.exit(1)
    
    # Checking that we actually have a file (!a directory)
    if not os.path.isfile(file_path):
        print(f"[!] Error: Path is not a file: '{file_path}'")
        sys.exit(1)

    # Checking the file is readable
    if not os.access(file_path, os.R_OK):
        print(f"[!] Error: File is not readable (permission denied): '{file_path}'")
        sys.exit(1)
    
    # Checking is a supported extension
    ALLOWED_EXTENSIONS = {".eml", ".txt"}
    _, ext = os.path.splitext(file_path)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        print(f"[!] Error: Unsupported file type '{ext}'. Supported file types: {ALLOWED_EXTENSIONS}")
        sys.exit(1)

    # Call run_analysis() and let it print
    if not args.report:
        run_analysis(file_path, use_json=args.json, show_mime=args.mime)
    else:
        now = datetime.now()
        filename_timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
        pdf_path = args.output if args.output else f"phish-report-analysis-{filename_timestamp}.pdf"

        # Ensure the path specified exists before starting to generate the report PDF
        if args.output:
            output_dir = os.path.dirname(os.path.abspath(pdf_path))
            os.makedirs(output_dir, exist_ok=True)

        print("Starting Analysis with PDF Report Generation...")
        spinner = Halo(text="Analyzing email", spinner="dots")
        spinner.start()
        run_analysis_and_pdf(args.file, pdf_path, show_mime=args.mime)
        spinner.stop()
        print(f"Report Generated: {pdf_path}")

if __name__ == "__main__":
    main()