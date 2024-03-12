import argparse
import base64
import hashlib
import logging
import sys
from pathlib import Path

import requests
import urllib3
from pygroupsig import (
    constants,
    groupsig,
    grpkey,
    memkey,
    message,
    signature,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SCHEMES = {
    "kty04": constants.KTY04_CODE,
    # "bbs04": constants.BBS04_CODE,
    "cpy06": constants.CPY06_CODE,
    "gl19": constants.GL19_CODE,
    "ps16": constants.PS16_CODE,
    # "klap20": constants.KLAP20_CODE,
}
CRL = [constants.KTY04_CODE, constants.CPY06_CODE]
TWO = [
    constants.KTY04_CODE,
    constants.CPY06_CODE,
]  # , constants.BBS04_CODE]


def twophase(code):
    if code in TWO:
        return True
    return False


def decode(resp, msg):
    try:
        return resp.json()
    except requests.JSONDecodeError:
        logging.error(msg)
        sys.exit(1)


class Producer:
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

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        groupsig.clear(self.code)

    def register(self):
        if self.memkey is None and self.grpkey is not None:
            if twophase(self.code):
                msg1 = groupsig.join_mem(0, self.grpkey)
                msgout = message.message_to_base64(msg1["msgout"])
                res = self.sess.post(
                    f"{self.url}/groupsig/join",
                    data={"phase": 1, "message": msgout},
                )
                data = decode(res, "Decoding join_1 message")
                if data["status"] == "success":
                    self.memkey = memkey.memkey_import(
                        self.code, data["msg"]
                    )
                else:
                    logging.error(data["msg"])
                    return data["msg"]
            else:
                res = self.sess.post(
                    f"{self.url}/groupsig/join", data={"phase": 0}
                )
                data = decode(res, "Decoding join_0 message")
                if data["status"] == "success":
                    msg1 = message.message_from_base64(data["msg"])
                    msg2 = groupsig.join_mem(1, self.grpkey, msgin=msg1)
                    msgout = message.message_to_base64(msg2["msgout"])
                    res2 = self.sess.post(
                        f"{self.url}/groupsig/join",
                        data={"phase": 2, "message": msgout},
                    )
                    data2 = decode(res2, "Decoding join_2 message")
                    msg3 = message.message_from_base64(data2["msg"])
                    msg4 = groupsig.join_mem(
                        3, self.grpkey, msgin=msg3, memkey=msg2["memkey"]
                    )
                    self.memkey = msg4["memkey"]
                else:
                    logging.error(data["msg"])
                    return data["msg"]
            self._save_crypto()
            return memkey.memkey_export(self.memkey)
        else:
            logging.error("Already registered")

    def sign(self):
        if self.memkey is not None and self.grpkey is not None:
            with self.args.asset.open("rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            sig = signature.signature_export(
                groupsig.sign(digest, self.memkey, self.grpkey)
            )
            with self.args.sig.open("w") as f:
                f.write(sig)
            return sig
        else:
            logging.error("Missing memkey or grpkey")

    def verify(self):
        if self.grpkey is not None:
            with self.args.asset.open("rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            with self.args.sig.open() as f:
                sig = signature.signature_import(self.code, f.read())
            ver = groupsig.verify(sig, digest, self.grpkey)
            logging.info(f"Signature verified: {ver}")
            return ver
        else:
            logging.error("Missing grpkey")

    def _retrieve_grpkey(self):
        res = self.sess.get(f"{self.url}/groupsig")
        data = decode(res, "Decoding groupkey message")
        grpkey_bytes = base64.b64decode(data["msg"])
        self.code = grpkey_bytes[0]
        groupsig.init(self.code)
        self.grpkey = grpkey.grpkey_import(self.code, data["msg"])
        self._save_crypto()

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
                    groupsig.init(self.code)
                    self.grpkey = grpkey.grpkey_import(
                        self.code, data
                    )
            else:
                self._retrieve_grpkey()
        if self.memkey is None:
            if self.args.mkey.is_file():
                with self.args.mkey.open() as f:
                    self.memkey = memkey.memkey_import(
                        self.code, f.read()
                    )


def parse_args():
    parser = argparse.ArgumentParser(description="Groupsig client")
    func = parser.add_mutually_exclusive_group(required=True)
    func.add_argument(
        "--register",
        "-r",
        action="store_true",
        help="Join group using certificate identity",
    )
    func.add_argument(
        "--sign", "-s", action="store_true", help="Sign asset digest"
    )
    func.add_argument(
        "--verify",
        "-v",
        action="store_true",
        help="Verify signature, i.e. issued by a group",
    )
    parser.add_argument(
        "--host",
        "-H",
        metavar="HOST",
        required=True,
        # default="localhost",
        help="Group signature API host/IP",
    )
    parser.add_argument(
        "--port",
        "-P",
        metavar="PORT",
        type=int,
        default=5000,
        help="Group signature API port",
    )
    parser.add_argument(
        "--cert",
        "-C",
        metavar="CERT",
        type=Path,
        required=True,
        # default="gicp_api/crypto/producers/usr1.crt",
        help="Client certificate",
    )
    parser.add_argument(
        "--key",
        "-K",
        metavar="KEY",
        type=Path,
        required=True,
        # default="gicp_api/crypto/producers/usr1.key",
        help="Client certificate key",
    )
    parser.add_argument(
        "--gkey",
        "-g",
        metavar="PATH",
        default=Path("gkey"),
        type=Path,
        help="Group key file",
    )
    parser.add_argument(
        "--mkey",
        "-m",
        metavar="PATH",
        default=Path("mkey"),
        type=Path,
        help="Member key file",
    )
    parser.add_argument(
        "--sig",
        "-S",
        metavar="PATH",
        default=Path("sig"),
        type=Path,
        help="Signature file",
    )
    parser.add_argument(
        "--asset", "-a", metavar="PATH", type=Path, help="Asset file"
    )
    args = parser.parse_args()
    if (args.sign or args.verify) and args.asset is None:
        parser.error(
            "The --asset/-a argument is required when "
            "using --sign/-s or --verify/-v"
        )
    return args


def main(args):
    with Producer(args) as prod:
        if args.register:
            print(prod.register())
        if args.sign:
            print(prod.sign())
        if args.verify:
            print(prod.verify())


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    args = parse_args()
    main(args)
