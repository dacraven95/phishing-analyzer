#!/usr/bin/env python3
import argparse
import os
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

    args = parser.parse_args()

    # Call run_analysis() and let it print
    if not args.report:
        run_analysis(args.file, use_json=args.json)
    else:
        now = datetime.now()
        filename_timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
        pdf_path = args.output if args.output else f"phish-report-analysis-{filename_timestamp}.pdf"

        # Ensure the path specified exists before starting to generate the report PDF
        if args.output:
            output_dir = os.path.dirname(pdf_path)
            os.makedirs(output_dir, exist_ok=True)

        print("Starting Analysis with PDF Report Generation...")
        spinner = Halo(text="Analyzing email", spinner="dots")
        spinner.start()
        run_analysis_and_pdf(args.file, pdf_path)
        spinner.stop()
        print(f"Report Generated: {pdf_path}")

if __name__ == "__main__":
    main()