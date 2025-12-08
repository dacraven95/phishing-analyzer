#!/usr/bin/env python3
import argparse
from phish_analyzer.core import run_analysis

def main():
    parser = argparse.ArgumentParser(...)
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")

    args = parser.parse_args()

    # Call run_analysis() and let it print
    run_analysis(args.file, use_json=args.json)

if __name__ == "__main__":
    main()