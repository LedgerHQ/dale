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

## File format

DALE reads APDU files with the following content:
```
# Comment
=> <APDU>
<= <RAPDU>
# Example
=> e003000500102020
<= 9000
```

DALE can also extract the APDU content from Ledger Live logs.

### Reverted logs

Warning: sometimes the Ledger Live does not record the APDU logs in the correct order.
If you encounter errors using DALE while decoding logs you may try to use the `--reverse` command line option. 
