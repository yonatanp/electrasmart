"""Cmdline tools
"""
import sys
import json
import re
from pprint import pprint
from argparse import ArgumentParser

from .client import send_otp_request, get_otp_token, get_devices, AC


def auth():
    parser = ArgumentParser("Auth token generator")
    parser.add_argument("phone", help="the phone registered to the AC (as a string of digits, e.g. '0524001234')")
    args = parser.parse_args()

    phone = args.phone
    phonePattern = "[0-9]{10}"
    otpPattern = "[0-9]{4}"

    m = re.match(phonePattern, phone)
    if m:
        imei = send_otp_request(phone)
        otp = input(f"Please enter the OTP password received at {phone}: ")

        m = re.match(otpPattern, otp)
        if m:
            imei, token = get_otp_token(imei, phone, otp)

            print("Use the following auth parameters for instantiating your AC class:")
            print(f"  - imei: {imei}")
            print(f"  - token: {token}")
        else:
            print(f" OTP code: {otp} is invalid")
    else:
        print(f" phone number: {phone} is invalid")


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
    parser = ArgumentParser("Generate baseline status")
    _add_ac_arguments(parser)
    parser.add_argument("output_file", default=None, help="target where baseline status is saved (default: baseline_status_<ac_id>.json)")
    args = parser.parse_args()
    if args.output_file is None:
        args.output_file = f"baseline_status_{args.ac_id}.json"
    ac = AC(args.imei, args.token, args.ac_id)
    sid = ac.renew_sid()
    print(f"renewed sid: {sid})
    status = ac.status(check=False)
    f = open(args.output_file, "w") if args.output_file != "-" else sys.stdout
    json.dump(status, f)
    print(f"Baseline status for AC id {args.ac_id} written successfully to "
          f"{args.output_file if args.output_file != '-' else 'stdout'}")


def send_command():
    parser = ArgumentParser("Send command to the AC unit")
    _add_ac_arguments(parser)
    parser.add_argument("--ac-mode", default=None, help="set the AC mode",
                        choices=["STBY", "COOL", "FAN", "DRY", "HEAT", "AUTO"])  # TODO: take from constants module
    parser.add_argument("--fan-speed", default=None, help="set the fan speed",
                        choices=["LOW", "MED", "HIGH", "AUTO"])
    parser.add_argument("--temperature", default=None, type=int, help="set the target temperature")
    args = parser.parse_args()
    oper_kwargs = {}
    if args.ac_mode is not None:
        oper_kwargs['ac_mode'] = args.ac_mode
    if args.fan_speed is not None:
        oper_kwargs['fan_speed'] = args.fan_speed
    if args.temperature is not None:
        oper_kwargs['temperature'] = args.temperature
    if not oper_kwargs:
        parser.exit(message="no change was requested, aborting")
    ac = AC(args.imei, args.token, args.ac_id)
    sid = ac.renew_sid()
    print(f"renewed sid: {sid})
    ac.modify_oper(**oper_kwargs)


def _add_ac_arguments(parser):
    _add_auth_arguments(parser)
    parser.add_argument("ac_id", help="the id of the air conditioner as provided by electrasmart-list-devices")


def _add_auth_arguments(parser):
    parser.add_argument("imei", help="the `imei` string as provided by electrasmart-auth")
    parser.add_argument("token", help="the `token` string as provided by electrasmart-auth")
