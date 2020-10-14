"""Cmdline tools
"""
import sys
import json
from pprint import pprint
from argparse import ArgumentParser

from .client import generate_token, get_devices, AC


def auth():
    parser = ArgumentParser("Auth token generator")
    parser.add_argument("phone", help="the phone registered to the AC (as a string of digits, e.g. '0524001234')")
    args = parser.parse_args()

    imei, token = generate_token(args.phone)
    print("Use the following auth parameters for instantiating your AC class:")
    print(f"  - imei: {imei}")
    print(f"  - token: {token}")


def list_devices():
    parser = ArgumentParser("Auth token generator")
    _add_auth_arguments(parser)
    args = parser.parse_args()
    devices = get_devices(args.imei, args.token)
    for device in devices:
        print(f"*** device id: {device['id']} ***")
        if device.get("name"):
            print(f"User provided name: {device['name']}")
        print("Full details:")
        pprint(device)
        print()


def gen_baseline_status():
    parser = ArgumentParser("Auth token generator")
    _add_ac_arguments(parser)
    parser.add_argument("output_file", default=None, help="target where baseline status is saved (default: baseline_status_<ac_id>.json)")
    args = parser.parse_args()
    if args.output_file is None:
        args.output_file = f"baseline_status_{args.ac_id}.json"
    ac = AC(args.imei, args.token, args.ac_id)
    ac.renew_sid()
    status = ac.status(check=False)
    f = open(args.output_file, "w") if args.output_file != "-" else sys.stdout
    json.dump(status, f)
    print(f"Baseline status for AC id {args.ac_id} written successfully to "
          f"{args.output_file if args.output_file != '-' else 'stdout'}")


def _add_ac_arguments(parser):
    _add_auth_arguments(parser)
    parser.add_argument("ac_id", help="the id of the air conditioner as provided by electrasmart-list-devices")


def _add_auth_arguments(parser):
    parser.add_argument("imei", help="the `imei` string as provided by electrasmart-auth")
    parser.add_argument("token", help="the `token` string as provided by electrasmart-auth")
