#!/usr/bin/env python3

import logging
from argparse import ArgumentParser, RawTextHelpFormatter
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple, Optional

from dale.base import Response, APDUPair
from dale.exchange import factory as exchange_factory
from dale.parser import DefaultAPDUParser


def init_parser() -> ArgumentParser:
    parser = ArgumentParser(description="Explicit logging of a list of APDUs",
                            formatter_class=RawTextHelpFormatter)
    parser.add_argument("apdu_file", metavar="APDU_FILE", help="The file containing the list of APDUs", type=Path)
    return parser


def main():
    logging.root.setLevel(logging.INFO)

    parser = init_parser()
    args = parser.parse_args()
    apdu_file = args.apdu_file.resolve()
    assert apdu_file.is_file(), f"'{apdu_file}' does not exist or is not a file! Aborting"
    logging.info("Reading from %s", apdu_file)

    with apdu_file.open() as filee:
        with DefaultAPDUParser(exchange_factory) as apdu_parser:
            for line in filee:
                apdu_parser.feed(line)

    for exchange in apdu_parser.conversation:
        print(str(exchange))

    print('='*45)
    print('Finished.')

if __name__ == '__main__':
    main()
