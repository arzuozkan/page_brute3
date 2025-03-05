#!/usr/bin/python3
#
# page_brute.py - Python 3 uyumlu
# by @matonis - secualexploits.blogspot.com - www.mike-matonis.com
# converted python2 to python3 with chatgpt

import sys
import argparse
import datetime
import glob
import os
import os.path
import binascii

try:
    import yara
except ImportError:
    print("[!] - ERROR: Could not import YARA...")
    print("...did you install yara and yara-python? Exiting.")
    sys.exit()

def is_block_null(block):
    RAW_BLOCK = binascii.hexlify(block).decode()
    NULL_REF = binascii.hexlify(NULL_REFERENCE.encode()).decode()
    return RAW_BLOCK == NULL_REF

def build_ruleset():
    if RULETYPE == "FILE":
        try:
            rules = yara.compile(str(RULES))
            print("..... Ruleset Compilation Successful.")
            return rules
        except Exception as e:
            print(f"[!] - Could not compile YARA rule: {RULES}")
            print(f"Error: {e}\nExiting.")
            sys.exit()

    elif RULETYPE == "FOLDER":
        RULEDATA = ""
        RULE_COUNT = len(glob.glob1(RULES, "*.yar"))
        if RULE_COUNT != 0:
            for yara_file in glob.glob(os.path.join(RULES, "*.yar")):
                try:
                    yara.compile(str(yara_file))
                    print(f"..... Syntax appears to be OK: {yara_file}")
                    with open(yara_file, "r", encoding="utf-8") as sig_file:
                        RULEDATA += "\n" + sig_file.read()
                except Exception as e:
                    print(f"..... SKIPPING: Could not compile rule: {yara_file} - {e}")
            try:
                rules = yara.compile(source=RULEDATA)
                print("..... SUCCESS! Compiled noted yara rulesets.\n")
                return rules
            except Exception as e:
                print(f"[!] - Compilation error: {e}. Exiting.")
                sys.exit()
        else:
            print(f"No files ending in .yar within: {RULES}")
            print("Exiting.")
            sys.exit()

    elif RULETYPE == "DEFAULT":
        return yara.compile(str(RULES))
    else:
        print("[!] - ERROR: Possible catastrophic error on build_ruleset. Exiting.")
        sys.exit()

def print_procedures():
    print("[+] - PAGE_BRUTE running with the following options:")
    print(f"\t[-] - FILE: {FILE}")
    print(f"\t[-] - PAGE_SIZE: {PAGE_SIZE}")
    print(f"\t[-] - RULES TYPE: {RULETYPE}")
    print(f"\t[-] - RULE LOCATION: {RULES}")
    print(f"\t[-] - INVERSION SCAN: {INVERT}")
    print(f"\t[-] - WORKING DIR: {WORKING_DIR}\n")

def main():
    global FILE, PAGE_SIZE, RULES, SCANNAME, INVERT, RULETYPE, NULL_REFERENCE, WORKING_DIR

    argument_parser = argparse.ArgumentParser(description="Checks pages in pagefiles for YARA-based rule matches.")
    argument_parser.add_argument("-f", "--file", metavar="FILE", required=True, help="Pagefile or binary file")
    argument_parser.add_argument("-p", "--size", metavar="SIZE", type=int, default=4096, help="Size of chunk/block in bytes (Default 4096)")
    argument_parser.add_argument("-o", "--scanname", metavar="SCANNAME", help="Descriptor of the scan session")
    argument_parser.add_argument("-i", "--invert", action='store_true', help="Match all blocks that DO NOT match a ruleset")
    argument_parser.add_argument("-r", "--rules", metavar="RULEFILE", help="File/directory containing YARA signatures")
    
    args = argument_parser.parse_args()

    FILE = args.file
    PAGE_SIZE = args.size
    NULL_REFERENCE = '\x00' * PAGE_SIZE
    SCANNAME = args.scanname if args.scanname else "PAGE_BRUTE-" + datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    INVERT = args.invert
    RULES = args.rules if args.rules else "default_signatures.yar"
    RULETYPE = "FILE" if os.path.isfile(RULES) else "FOLDER" if os.path.isdir(RULES) else "DEFAULT"

    if not os.path.exists(FILE):
        print(f"[!] - Could not open {FILE}. Exiting.")
        sys.exit()

    authoritative_rules = build_ruleset()
    WORKING_DIR = SCANNAME
    os.makedirs(WORKING_DIR, exist_ok=True)

    print_procedures()
    page_id = 0
    with open(FILE, "rb") as page_file:
        while True:
            raw_page = page_file.read(PAGE_SIZE)
            if not raw_page:
                print(f"Done!\nEnding page_id is: {page_id}")
                break
            if not is_block_null(raw_page):
                matched = False
                for matches in authoritative_rules.match(data=raw_page):
                    if INVERT:
                        matched = True
                    else:
                        CHUNK_OUTPUT_DIR = os.path.join(WORKING_DIR, matches.rule)
                        print(f"[!] FLAGGED BLOCK {page_id}: {matches.rule}")
                        os.makedirs(CHUNK_OUTPUT_DIR, exist_ok=True)
                        with open(os.path.join(CHUNK_OUTPUT_DIR, f"{page_id}.block"), "wb+") as page_export:
                            page_export.write(raw_page)
                if INVERT and not matched:
                    CHUNK_OUTPUT_DIR = os.path.join(WORKING_DIR, "INVERTED-MATCH")
                    print(f"[!] BLOCK {page_id} DOES NOT MATCH ANY KNOWN SIGNATURE")
                    os.makedirs(CHUNK_OUTPUT_DIR, exist_ok=True)
                    with open(os.path.join(CHUNK_OUTPUT_DIR, f"{page_id}.block"), "wb+") as page_export:
                        page_export.write(raw_page)
            page_id += 1

if __name__ == "__main__":
    main()
