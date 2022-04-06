# Dummy APDU Logger, Explained

This project aims at parsing all kind of APDU exchange files, and displaying
them in a understandable fashion.


## Install

From the top of the repo, given you have the right to install the package
(either root or in a `virtualenv`):

```
pip install .
```

## Usage

Once install, you should now have a `dale` command:

```
$ dale -h
usage: dale [-h] APDU_FILE

Explicit logging of a list of APDUs

positional arguments:
  APDU_FILE   The file containing the list of APDUs

optional arguments:
  -h, --help  show this help message and exit
```