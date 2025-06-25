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
    parser.add_argument("--json_input", action="store_true",
                        help="Read a Ledger Live log instead of a raw APDU file")
    parser.add_argument("--reverse", action="store_true",
                        help="Read APDU file in reverse order (bottom to top)")
    return parser


def main():
    logging.root.setLevel(logging.INFO)

    apdus: list[str] = []
    parser = init_parser()
    args = parser.parse_args()
    apdu_file = args.apdu_file.resolve()
    if not apdu_file.is_file():
        raise AssertionError(f"'{apdu_file}' does not exist or is not a file! Aborting")
    logging.info("Reading from %s", apdu_file)

    # check if input file is Ledger Live log
    if args.json_input:
        logging.info("Parsing Ledger Live log file")
        with apdu_file.open("r", encoding="utf8") as f:
            entries = json.load(f)

            # Extract the APDUs from the log
            # get the "message" field from each entry where the "type" is "apdu"
            dmk_logs = [
                x["message"]
                for x in entries
                if x.get("type", "") == "live-dmk-tracer"
            ]
            for line in dmk_logs:
                if line.startswith("[exchange] "):
                    apdus.append(line[len("[exchange] "):])
    else:
        logging.info("Reading raw APDU file")
        with apdu_file.open() as file:
            for line in file:
                apdus.append(line)

    if args.reverse:
        logging.info("Reversing lines")
        apdus.reverse()

    with DefaultAPDUParser([ExchangeFactory(), DefaultAPDUsFactory(), Factory()]) as apdu_parser:
        for apdu in apdus:
            apdu_parser.feed(apdu)

    for exchange in apdu_parser.conversation:
        print(str(exchange))

    print('=' * 45)
    print('Finished.')


if __name__ == '__main__':
    main()
