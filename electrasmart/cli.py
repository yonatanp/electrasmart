"""Cmdline tools
"""
from argparse import ArgumentParser
from .client import generate_token


def auth():
    parser = ArgumentParser("Auth token generator")
    parser.add_argument("phone", help="the phone registered to the AC (as a string of digits, e.g. '0524001234')")
    args = parser.parse_args()

    imei, token = generate_token(args.phone)
    print("Use the following auth parameters for instantiating your AC class:")
    print(f"  - imei: {repr(imei)}")
    print(f"  - token: {repr(token)}")
