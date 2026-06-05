#!/usr/bin/env python3

import json
import logging
from argparse import ArgumentParser, RawTextHelpFormatter
from pathlib import Path

from dale.base import Factory
from dale.exchange import ExchangeFactory
from dale.default_apdus import DefaultAPDUsFactory
from dale.parser import DefaultAPDUParser


def init_parser() -> ArgumentParser:
    parser = ArgumentParser(description="Explicit logging of a list of APDUs",
                            formatter_class=RawTextHelpFormatter)
    parser.add_argument("apdu_file", metavar="APDU_FILE",
                        help="The file containing the list of APDUs",
                        type=Path)
    parser.add_argument("--reverse", action="store_true",
                        help="Read APDU file in reverse order (bottom to top)")
    return parser


# Extract APDU lines from a Ledger Live JSON log
def _extract_apdus_from_json(text: str) -> list[str]:
    apdus: list[str] = []
    entries = json.loads(text)
    dmk_logs = [
        x
        for x in entries
        if x.get("type", "") == "live-dmk-tracer" or x.get("type", "") == "live-dmk-logger"
    ]
    for entry in dmk_logs:
        if entry["message"] == "[sendApdu]":
            apdus.append("=> " + entry["data"]["data"]["apdu"]["hex"][len("0x"):])
        elif entry["message"] == "Received APDU Response":
            data = entry["data"]["data"]["response"]["data"]["hex"][len("0x"):]
            status_code = entry["data"]["data"]["response"]["statusCode"]["hex"][len("0x"):]
            apdus.append("<= " + data + status_code)
    return apdus


# Extract APDU lines from a raw text file
def _extract_apdus_from_raw(text: str) -> list[str]:
    return text.splitlines(keepends=True)


# Detect if the input text is a Ledger Live JSON log
def _is_json_input(text: str) -> bool:
    try:
        entries = json.loads(text)
        if not isinstance(entries, list):
            return False
        return any(
            x.get("type", "") in ("live-dmk-tracer", "live-dmk-logger")
            for x in entries
        )
    except (json.JSONDecodeError, AttributeError):
        return False


# Core processing: takes raw file content as text, returns the decoded APDU output as a string
def process_text(text: str, reverse: bool = False) -> str:
    if _is_json_input(text):
        apdus = _extract_apdus_from_json(text)
    else:
        apdus = _extract_apdus_from_raw(text)

    if reverse:
        apdus.reverse()

    with DefaultAPDUParser([ExchangeFactory(), DefaultAPDUsFactory(), Factory()]) as apdu_parser:
        for apdu in apdus:
            apdu_parser.feed(apdu)

    lines = [str(exchange) for exchange in apdu_parser.conversation]
    lines.append('=' * 45)
    lines.append('Finished.')
    return '\n'.join(lines)


# Entry point for the local python cli version
def main():
    logging.root.setLevel(logging.INFO)

    parser = init_parser()
    args = parser.parse_args()
    apdu_file = args.apdu_file.resolve()
    if not apdu_file.is_file():
        raise AssertionError(f"'{apdu_file}' does not exist or is not a file! Aborting")
    logging.info("Reading from %s", apdu_file)

    with apdu_file.open("r", encoding="utf8") as f:
        text = f.read()

    print(process_text(text, reverse=args.reverse))


# Return extracted APDU lines if input is JSON, empty string otherwise (for web intermediate display)
def extract_apdus_web(text: str, reverse: bool = False) -> str:
    if not _is_json_input(text):
        return ''
    apdus = _extract_apdus_from_json(text)
    if reverse:
        apdus.reverse()
    return '\n'.join(apdus)


# Entry point for the web version (called from Pyodide in index.html)
def main_web(text: str, reverse: bool = False) -> str:
    return process_text(text, reverse=reverse)


if __name__ == '__main__':
    main()
