import argparse
import errno
import json
import logging
import os
import sys
import tempfile
import hashlib
import base64
from pathlib import Path
import sys

import requests
import urllib3
from pygroupsig import constants, groupsig, grpkey, memkey, message, signature

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SCHEMES = {
    "ps16": constants.PS16_CODE,
    "gl19": constants.GL19_CODE,
    "kty04": constants.KTY04_CODE,
    # "ps16": 1,
    # "gl19": 2,
    # "kty04": 3,
}


def crl_scheme(code):
    if code == constants.KTY04_CODE:
        return True
    return False


def twophase_scheme(code):
    if code in [constants.KTY04_CODE]:# , constants.BBS04_CODE]:
        return True
    return False


def decode(resp, msg):
    try:
        return resp.json()
    except requests.JSONDecodeError:
        logging.error(msg)
        sys.exit(1)


class User:
    def __init__(self, args):
        self.args = args
        self.url = f"https://{args.host}:{args.port}"
        self.sess = requests.Session()
        self.sess.verify = False
        self.sess.cert = (args.cert, args.key)
        self.code = None
        self.grpkey = None
        self.memkey = None
        self._load_crypto()

    def join(self):
        if self.memkey is None:
            if twophase_scheme(self.code):
                msg1 = groupsig.join_mem(0, self.grpkey)
                msgout = message.message_to_base64(msg1)
                res = self.sess.post(
                    f'{self.url}/groupsig/join',
                    data={"phase": 1, "message": msgout}
                )
                data = decode(res, "Decoding join_1 message")
                self.memkey = message.message_from_base64(data["msg"])
            else:
                res = self.sess.post(
                    f'{self.url}/groupsig/join', data={"phase": 0})
                data = decode(res, "Decoding join_0 message")
                msg1 = message.message_from_base64(data["msg"])
                msg2 = groupsig.join_mem(1, self.grpkey, msgin=msg1)
                msgout = message.message_to_base64(msg2["msgout"])
                res2 = self.sess.post(
                    f'{self.url}/groupsig/join',
                    data={"phase": 2, "message": msgout}
                )
                data2 = decode(res2, "Decoding join_2 message")
                msg3 = message.message_from_base64(data2["msg"])
                msg4 = groupsig.join_mem(
                    3, self.grpkey, msgin=msg3, memkey=msg2["memkey"])
                self.memkey = msg4['memkey']
            self._save_crypto()

    def sign(self):
        with self.args.asset.open("rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        with self.args.sig.open("w") as f:
            f.write(signature.signature_export(
            groupsig.sign(digest, self.memkey, self.grpkey)))

    def verify(self):
        with self.args.asset.open("rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        with self.args.sig.open() as f:
            sig = signature.signature_import(self.code, f.read())
            ver = groupsig.verify(sig, digest, self.grpkey)
            logging.info(f"Status: {ver}")
            return ver

    def _retrieve_grpkey(self):
        res = self.sess.get(f'{self.url}/groupsig')
        try:
            data = res.json()
        except requests.JSONDecodeError:
            logging.error("Decoding groupkey message")
        else:
            grpkey_bytes = base64.b64decode(data["msg"])
            self.code = grpkey_bytes[0]
            if not crl_scheme(self.code):
                groupsig.init(self.code)
            self.grpkey = grpkey.grpkey_import(self.code, data["msg"])

    def _save_crypto(self):
        if self.grpkey is not None:
            with self.args.gkey.open("w") as f:
                f.write(grpkey.grpkey_export(self.grpkey))
        if self.memkey is not None:
            with self.args.mkey.open("w") as f:
                f.write(memkey.memkey_export(self.memkey))

    def _load_crypto(self):
        if self.grpkey is None:
            if self.args.gkey.is_file():
                with self.args.gkey.open() as f:
                    data = f.read()
                    grpkey_bytes = base64.b64decode(data)
                    self.code = grpkey_bytes[0]
                    if not crl_scheme(self.code):
                        groupsig.init(self.code)
                    self.grpkey = grpkey.grpkey_import(self.code, data)
            else:
                self._retrieve_grpkey()
        if self.memkey is None:
            if self.args.mkey.is_file():
                with self.args.mkey.open() as f:
                    self.memkey = memkey.memkey_import(self.code, f.read())


def parse_args():
    parser = argparse.ArgumentParser(description="GroupSig client")
    func = parser.add_mutually_exclusive_group(required=True)
    func.add_argument(
        "--register", "-r",
        action="store_true",
        help="Join group using certificate identity"
    )
    func.add_argument(
        "--sign", "-s",
        action="store_true",
        help="Sign asset digest"
    )
    func.add_argument(
        "--verify", "-v",
        action="store_true",
        help="Verify signature"
    )
    func.add_argument(
        "--status", "-S",
        action="store_true",
        help="Check signature status"
    )
    func.add_argument(
        "--revoke", "-k",
        action="store_true",
        help="Revoke signature"
    )
    parser.add_argument(
        "--host", "-H",
        metavar="HOST",
        default="localhost",
        help="Group signature API host/IP"
    )
    parser.add_argument(
        "--port", "-P",
        metavar="PORT",
        type=int,
        default=5000,
        help="Group signature API port",
    )
    parser.add_argument(
        "--cert", "-C",
        metavar="CERT",
        type=Path,
        default="gicp_api/crypto/auditors/user1.crt",
        help="Client certificate"
    )
    parser.add_argument(
        "--key", "-K",
        metavar="KEY",
        type=Path,
        default="gicp_api/crypto/auditors/user1.key",
        help="Client certificate key"
    )
    parser.add_argument(
        "--gkey", "-g",
        metavar="PATH",
        default=Path("gkey"),
        type=Path,
        help="Group key file"
    )
    parser.add_argument(
        "--mkey", "-m",
        metavar="PATH",
        default=Path("mkey"),
        type=Path,
        help="Member key file"
    )
    parser.add_argument(
        "--sig", "-G",
        metavar="PATH",
        default=Path("sig"),
        type=Path,
        help="Signature file"
    )
    parser.add_argument(
        "--asset", "-a",
        metavar="PATH",
        type=Path,
        help="Asset file"
    )
    args = parser.parse_args()
    if (args.sign or args.verify) and args.asset is None:
        parser.error("The --asset/-a argument is required when "
                     "using --sign/-s or --verify/-v")
    return args


def main(args):
    import pdb; pdb.set_trace()
    user = User(args)
    if args.register:
        user.join()
    if args.sign:
        user.sign()
    if args.verify:
        user.verify()
    if args.status:
        user.status()
    if args.revoke: # only allowed on certain entities
        user.revoke()

    if not crl_scheme(user.code):
        groupsig.clear(user.code)


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    args = parse_args()
    main(args)
