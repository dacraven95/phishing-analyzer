#!/usr/bin/env python3

import os
import argparse
import re
from email import message_from_string
from email.policy import default as default_policy
from email.utils import parseaddr
from colors import RED, GREEN, YELLOW, BLUE, RESET, CYAN, BRIGHT_GREEN, MAGENTA, BRIGHT_RED

def print_banner():
    banner = r"""
==========================================================
   PHISH ANALYZER - Email Header Scanner - Version: 0.1
   Author: Creaola
==========================================================
"""
    print(BRIGHT_GREEN + banner + RESET)

def extract_header_block(raw: str) -> str:
    """
    Extracts the header block from text, even if there is extra text before/after.
    Headers end at the first blank line.
    """
    lines = raw.splitlines()

    # Find the first "start" of a header: a line containing "Something:"  
    # and then gather everything until the first blank line.
    header_started = False
    header_lines = []
    
    for line in lines:
        if not header_started:
            if ":" in line and "#" not in line:           
                header_started = True
                header_lines.append(line)
        else:
            if line.strip() == "":    # blank line = end of headers
                break
            header_lines.append(line)

    return "\n".join(header_lines)

def parse_full_eml(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    return message_from_string(raw, policy=default_policy)

def parse_headers_from_file(path: str):
    """
    Read raw header text from a file and parse into an email Message object.
    
    :param path: Path to headers text file.
    :type path: str
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    # Extract header block from text file
    header_block = extract_header_block(raw)

    msg = message_from_string(header_block, policy=default_policy)
    return msg

def get_domain_from_address(header_value: str | None) -> str | None:
    """
    Extract domain from an email address header like 'Name <user@example.com>'
    
    :param header_value: Description
    :type header_value: str | None
    :return: Description
    :rtype: str | None
    """
    
    # Validation checks
    if not header_value:
        return None
    
    display_name, email_addr = parseaddr(header_value)
    if "@" not in email_addr:
        return None
    
    # Return lowercase domain name from email
    return email_addr.split("@", 1)[1].lower()

def parse_received_spf(spf_header: str):
    """
    Extracts SPF result (pass/fail/etc) and client-ip from a Received-SPF header.
    Returns dict like:
    {
        "result": "fail",
        "client_ip": "74.120.121.159"
    }
    """

    # SPF result appears at the very beginning, e.g.:
    # "Fail (....)" or "Pass (....)"
    result_match = re.match(r"\s*([A-Za-z]+)", spf_header)
    result = result_match.group(1).lower() if result_match else None

    # Extract client-ip=...
    ip_match = re.search(r"client-ip=([\d\.]+)", spf_header)
    client_ip = ip_match.group(1) if ip_match else None

    return {
        "result": result,
        "client_ip": client_ip
    }

def has_crosstenant_headers(headers: dict) -> bool:
    """
    Returns True if any header name or value contains 'crosstenant'
    (case-insensitive).
    """
    for key, value in headers.items():
        if "crosstenant" in key.lower() or ("crosstenant" in value.lower() if value else False):
            return True
    return False

def main():
    parser = argparse.ArgumentParser(
        description="Step 1: just parse and print basic email headers."
    )

    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Path to a text file containing raw email headers.",
    )

    args = parser.parse_args()

    # Get file extension
    filename = args.file
    _, ext = os.path.splitext(filename)
    ext = ext.lower()

    if ext == ".eml":
        # Handle EML file
        print(GREEN + "[+] Detected EML file" + RESET)
        print()
        msg = parse_full_eml(filename)
    else:
        # Handle as TXT file
        print(YELLOW + "[*] Treating file as raw headers" + RESET)
        print()
        msg = parse_headers_from_file(filename)

    from_hdr = msg["From"]
    to_hdr = msg["To"]
    reply_to_hdr = msg["Reply-To"]
    return_path_hdr = msg["Return-Path"]
    date_hdr = msg["Date"]
    subject_hdr = msg["Subject"]
    mime_version_hdr = msg["MIME-Version"]
    content_language_hdr = msg["Content-Language"]
    content_type_hdr = msg["Content-Type"]
    thread_topic_hdr = msg["Thread-Topic"]
    org_authAs_hdr = msg["X-MS-Exchange-Organization-AuthAs"]
    auth_results_hdr = msg["authentication-results"]

    # Parse received-spf
    received_spf_hdrs = msg.get_all("received-spf") or []

    # Rule:
    # - The first header is the most recent hop
    # - Earlier ones are historical and less relevant to final evaluation
    if received_spf_hdrs:
        primary_spf_header = received_spf_hdrs[0]
        parsed_spf_hdr = parse_received_spf(primary_spf_header)
    
    # Check for CrossTenant Headers
    crossTenant = has_crosstenant_headers(msg)

    # Output Analysis
    print(f"{CYAN}=== Raw Header Values ==={RESET}")
    print(f"From:           {from_hdr!r}")
    print(f"To:             {to_hdr!r}")
    print(f"Reply-To:       {reply_to_hdr!r}")
    print(f"Return-Path:    {return_path_hdr!r}")
    print()
    print(f"Thread-Topic:   {thread_topic_hdr!r}")
    print(f"Subject:        {subject_hdr!r}")
    print(f"Date:           {date_hdr!r}")
    print()
    print(f"Content-Type:     {content_type_hdr!r}")
    print(f"Content-Language: {content_language_hdr!r}")
    print()
    if parsed_spf_hdr["result"] == 'pass':
        print(f"{BRIGHT_GREEN}received-spf:{RESET}   {received_spf_hdrs[0]!r}")
    if parsed_spf_hdr["result"] == 'fail':
        print(f"{BRIGHT_RED}received-spf:{RESET}   {received_spf_hdrs[0]!r}")
    print()
    print(f"MIME-Version:   {mime_version_hdr!r}")
    print()

    print(f"{CYAN}=== Parsed Domains ==={RESET}")
    from_domain = get_domain_from_address(from_hdr)
    to_domain = get_domain_from_address(to_hdr)
    reply_to_domain = get_domain_from_address(reply_to_hdr)
    return_path_domain = get_domain_from_address(return_path_hdr)

    print(f"From domain:            {from_domain}")
    print(f"To domain:              {to_domain}")
    if from_domain != to_domain and crossTenant:
        print(f"{BRIGHT_GREEN}Cross Tenant:   {crossTenant}{RESET}")
    if from_domain == to_domain and crossTenant:
        print(f"{BRIGHT_RED}Cross Tenant:   {crossTenant}{RESET}")
    print(f"Reply-To domain:        {reply_to_domain}")
    print(f"Return-Path domain:     {return_path_domain}")
    print()

    if from_domain == to_domain and crossTenant:
        print(f"{RED}=== Internal Spoofing evidence found ==={RESET}")
        print(f"Cross Tenant -> {crossTenant}")
        if org_authAs_hdr == "Anonymous":
            print(f"AuthAs -> {org_authAs_hdr}")
        if parsed_spf_hdr["result"] == "fail":
            print(f"SPF Failed -> Origin IP = {parsed_spf_hdr["client_ip"]}")
    
    if from_domain != to_domain:
        if parsed_spf_hdr["result"] == "fail":
            print(f"{RED}=== External Spoofing evidence found ==={RESET}")
            print(f"SPF Failed -> Origin IP = {parsed_spf_hdr["client_ip"]}")
    
    print()
    # print(f"{YELLOW}=== Other Potentially Phishy Evidence ==={RESET}")
    # if parsed_spf_hdr["result"] == "fail" and from_domain != to_domain:
    #     print(f"SPF Failed -> Origin IP = {parsed_spf_hdr["client_ip"]}")
    
    print()


# Run main
if __name__ == "__main__":
    print_banner()
    main()