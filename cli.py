#!/usr/bin/env python3
import argparse
import os
import sys
from phish_analyzer.core import run_analysis, run_analysis_and_pdf
from phish_analyzer.threat_intel import (
    tag_campaign,
    tag_campaign_by_indicator,
    list_analyses,
    list_campaigns,
    get_campaign_iocs,
    export_iocs_json,
    export_iocs_csv,
    export_iocs_stix,
)
from datetime import datetime
from halo import Halo

def main():
    parser = argparse.ArgumentParser(...)
    parser.add_argument("-f", "--file", required=False, help="The email or header file needing to be anlyzed")
    parser.add_argument("-j", "--json", action="store_true", help="Output an analysis_results JSON object")
    parser.add_argument("--no-color", action="store_true", help="Do not color terminal output (NOT WORKING AT THE MOMENT)")
    parser.add_argument("-r","--report", action="store_true", help="Generate a PDF report instead of terminal output")
    parser.add_argument("-o","--output", type=str, help="Path to write the generated PDF report (CLI only)")
    parser.add_argument("-m", "--mime", action="store_true", help="Dump email MIME data on output")

    # --- New threat intel args ---
    parser.add_argument(
        "--tag",
        nargs=2,
        metavar=("ANALYSIS_ID", "CAMPAIGN_NAME"),
        help="Tag an analysis with a campaign name. Example: --tag 42 DocuSign-Spoof"
    )
    parser.add_argument(
        "--tag-indicator",
        nargs=2,
        metavar=("INDICATOR", "CAMPAIGN_NAME"),
        help="Tag all analyses containing an indicator. Example: --tag-indicator 185.1.2.3 Mycampaign"
    )
    parser.add_argument(
        "--list",
        nargs="?",
        const="all",
        metavar="CAMPAIGN_NAME",
        help="List recent analyses, optionally filtered by campaign name"
    )
    parser.add_argument(
        "--campaigns",
        action="store_true",
        help="List all campaign tags and their analysis counts"
    )
    parser.add_argument(
        "--campaign-iocs",
        metavar="CAMPAIGN_NAME",
        help="Show all IOCs associated with a campaign"
    )
    parser.add_argument(
        "--export",
        choices=["json", "csv", "stix"],
        metavar="FORMAT",
        help="Export IOCs in specified format: json, csv, or stix"
    )
    parser.add_argument(
        "--export-campaign",
        metavar="CAMPAIGN_NAME",
        help="Filter export to a specific campaign"
    )
    parser.add_argument(
        "--export-output",
        metavar="PATH",
        help="Directory to write export files to (default: current directory)"
    )

    args = parser.parse_args()


    # ------------------------------------------------------------------
    # Campaign tagging commands — these don't need a file
    # ------------------------------------------------------------------

    if args.tag:
        analysis_id_str, campaign_name = args.tag
        try:
            analysis_id = int(analysis_id_str)
        except ValueError:
            print(f"[!] Analysis ID must be a number, got: {analysis_id_str}")
            sys.exit(1)

        success = tag_campaign(analysis_id, campaign_name)
        if success:
            print(f"[+] Analysis #{analysis_id} tagged with campaign: '{campaign_name}'")
        else:
            print(f"[!] No analysis found with ID {analysis_id}")
        return

    if args.tag_indicator:
        indicator, campaign_name = args.tag_indicator
        count = tag_campaign_by_indicator(indicator, campaign_name)
        if count > 0:
            print(f"[+] Tagged {count} analysis/analyses containing '{indicator}' "
                  f"with campaign: '{campaign_name}'")
        else:
            print(f"[!] No analyses found containing indicator: '{indicator}'")
        return

    if args.list is not None:
        campaign_filter = None if args.list == "all" else args.list
        analyses = list_analyses(limit=20, campaign_tag=campaign_filter)

        if not analyses:
            print("[*] No analyses found.")
            return

        header = f"{'ID':>4}  {'Date':^12}  {'Risk':^4}  {'SE':^4}  {'Campaign':<20}  File"
        print(header)
        print("-" * len(header))

        for a in analyses:
            date  = (a["analyzed_at"] or "")[:10]
            risk  = str(a["risk_score"]) if a["risk_score"] is not None else "-"
            se    = str(a["se_score"])   if a["se_score"]   is not None else "-"
            camp  = (a["campaign_tag"] or "-")[:20]
            fname = os.path.basename(a["file_name"] or "-")
            print(f"{a['id']:>4}  {date:^12}  {risk:^4}  {se:^4}  {camp:<20}  {fname}")
        return

    if args.campaigns:
        campaigns = list_campaigns()
        if not campaigns:
            print("[*] No campaigns tagged yet.")
            return

        print(f"{'Campaign':<30}  {'Analyses':^8}  {'First Seen':^12}  {'Last Seen':^12}")
        print("-" * 70)
        for c in campaigns:
            print(
                f"{c['campaign_tag']:<30}  "
                f"{c['analysis_count']:^8}  "
                f"{c['first_seen'][:10]:^12}  "
                f"{c['last_seen'][:10]:^12}"
            )
        return

    if args.campaign_iocs:
        iocs = get_campaign_iocs(args.campaign_iocs)
        if not iocs:
            print(f"[!] No analyses found for campaign: '{args.campaign_iocs}'")
            return

        print(f"\n=== Campaign IOC Profile: {iocs['campaign_tag']} ===")
        print(f"Analyses in campaign: {iocs['analysis_count']}\n")

        if iocs["ips"]:
            print("IPs:")
            for ip in iocs["ips"]:
                print(f"  - {ip}")

        if iocs["domains"]:
            print("\nDomains:")
            for d in iocs["domains"]:
                print(f"  - {d['domain']}  ({d['context']})")

        if iocs["hashes"]:
            print("\nAttachment Hashes:")
            for h in iocs["hashes"]:
                print(f"  - SHA256: {h['sha256']}")
                print(f"    MD5:    {h['md5']}")
                print(f"    File:   {h['filename'] or 'unknown'}")

        if iocs["urls"]:
            print("\nURLs:")
            for url in iocs["urls"][:20]:  # cap at 20 for readability
                print(f"  - {url}")

        if iocs["mailers"]:
            print("\nMailer Strings:")
            for m in iocs["mailers"]:
                print(f"  - {m}")
        print()
        return
    
    if args.export:
        fmt         = args.export
        campaign    = args.export_campaign or None
        output_dir  = args.export_output or "."
        os.makedirs(output_dir, exist_ok=True)
        timestamp   = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        tag_slug    = f"_{campaign}" if campaign else ""

        if fmt == "json":
            data     = export_iocs_json(campaign_tag=campaign)
            out_path = os.path.join(output_dir, f"iocs{tag_slug}_{timestamp}.json")
            with open(out_path, "w") as f:
                f.write(data)
            print(f"[+] JSON export written to: {out_path}")

        elif fmt == "csv":
            exports = export_iocs_csv(campaign_tag=campaign)
            for ioc_type, csv_data in exports.items():
                out_path = os.path.join(output_dir, f"iocs_{ioc_type}{tag_slug}_{timestamp}.csv")
                with open(out_path, "w") as f:
                    f.write(csv_data)
                print(f"[+] CSV export written to: {out_path}")

        elif fmt == "stix":
            data     = export_iocs_stix(campaign_tag=campaign)
            out_path = os.path.join(output_dir, f"iocs{tag_slug}_{timestamp}.stix.json")
            with open(out_path, "w") as f:
                f.write(data)
            print(f"[+] STIX 2.1 bundle written to: {out_path}")

        return

    # ------------------------------------------------------------------
    # Original analysis flow — requires a file
    # ------------------------------------------------------------------

    if not args.file:
        parser.print_help()
        sys.exit(1)


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