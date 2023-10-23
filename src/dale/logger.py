#!/usr/bin/env python3

import logging
from argparse import ArgumentParser, RawTextHelpFormatter
from pathlib import Path

from dale.base import Factory
from dale.exchange import ExchangeFactory
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
    if not apdu_file.is_file():
        raise AssertionError(f"'{apdu_file}' does not exist or is not a file! Aborting")
    logging.info("Reading from %s", apdu_file)

    with apdu_file.open() as filee:
        with DefaultAPDUParser([ExchangeFactory(), Factory()]) as apdu_parser:
            for line in filee:
                apdu_parser.feed(line)

    for exchange in apdu_parser.conversation:
        print(str(exchange))

    print('=' * 45)
    print('Finished.')


if __name__ == '__main__':
    main()
