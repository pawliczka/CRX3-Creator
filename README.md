# CRX3-Creator

Python script for building google chrome extension crx3 package.
It is inspired by https://github.com/bellbind/crxmake-python.

## Usage:

    main.py PACKAGE_BASE_DIR

## Example

An example extension named 'sample' is provided in the root of repository
directory for testing purposes:

    $ python main.py sample
    $ ls
    $ sample sample.crx sample.pem

## Requires:

  $ pip install -r requirements.txt

## Resources:

- "crxmake-python": https://github.com/bellbind/crxmake-python
