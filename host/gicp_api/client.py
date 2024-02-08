import argparse
import errno
import json
import os
import sys

import requests
import urllib3
from pygroupsig import constants, groupsig, grpkey, memkey, message

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SCHEMES = {
    "ps16": constants.PS16_CODE,
    "gl19": constants.GL19_CODE,
    "kty04": constants.KTY04_CODE,
}


def parse_args():
    parser = argparse.ArgumentParser(description="groupsig client")
    func = parser.add_mutually_exclusive_group(required=True)
    func.add_argument(
        "--register", "-r", help="Join a group using credentials"
    )
    func.add_argument("--revoke", "-k", help="Revoke a signature")
    func.add_argument(
        "--status", "-s", help="Check signature membership status"
    )
    func.add_argument("--verify", "-v", help="Verify signature")
    parser.add_argument(
        "--scheme",
        "-m",
        choices=SCHEMES.keys(),
        required=True,
        help="Group signature scheme",
    )
    parser.add_argument(
        "--host", "-h", metavar="HOST", help="Group API host/IP"
    )
    parser.add_argument(
        "--port",
        "-p",
        metavar="PORT",
        type=int,
        default=5000,
        help="Group API port",
    )
    parser.add_argument(
        "--cert", "-c", metavar="CERT", help="Public certificate"
    )
    parser.add_argument(
        "--key", "-k", metavar="KEY", help="Certificate private key"
    )
    return parser.parse_args()


def main(args):
    user = User(
        (args.a, args.p),
        args.d,
        (f"{args.u}/{args.crt}", f"{args.u}/{args.key}"),
    )
    user.retrieve_grpkey()
    user.join1()
    user.join2()
    user.save_credentials()
    if args.scheme != "kty04":
        groupsig.clear(constants.GL19_CODE)


if __name__ == "__main__":
    args = parse_args()
    main(args)
