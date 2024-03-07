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


class Revoker:
    def __init__(self, args):
        self.args = args
        self.url = f"https://{args.host}:{args.port}"
        self.sess = requests.Session()
        self.sess.verify = False
        self.sess.cert = (args.cert, args.key)
        self.code = None
        self.codec = None
        self.grpkey = None
        self.grpkeyc = None
        self.memkey = None
        self._load_crypto()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        groupsig.clear(self.code)

    def register(self):
        if self.memkey is None:
            if twophase(self.code):
                msg1 = groupsig.join_mem(0, self.grpkey)
                msgout = message.message_to_base64(msg1["msgout"])
                res = self.sess.post(
                    f"{self.url}/groupsig/join",
                    data={"phase": 1, "message": msgout, "revoker": 1},
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
                    f"{self.url}/groupsig/join",
                    data={"phase": 0, "revoker": 1}
                )
                data = decode(res, "Decoding join_0 message")
                if data["status"] == "success":
                    msg1 = message.message_from_base64(data["msg"])
                    msg2 = groupsig.join_mem(1, self.grpkey, msgin=msg1)
                    msgout = message.message_to_base64(msg2["msgout"])
                    res2 = self.sess.post(
                        f"{self.url}/groupsig/join",
                        data={"phase": 2, "message": msgout, "revoker": 1},
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

    def verify(self, revoker=False):
        # I don't think we should implement verification for revoker
        # but whatever
        code = self.codec
        grpkey = self.grpkeyc
        if revoker:
            code = self.code
            grpkey = self.grpkey
        if grpkey is not None:
            with self.args.asset.open("rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            with self.args.sig.open() as f:
                sig = signature.signature_import(code, f.read())
            ver = groupsig.verify(sig, digest, grpkey)
            logging.info(f"Signature verified: {ver}")
            return ver
        else:
            logging.error("Missing grpkey")

    def revoke(self):
        with self.args.sig.open() as f:
            sig = f.read()
        res = self.sess.get(
            f"{self.url}/groupsig/revoke"
        )
        data = decode(res, "Decoding revoke token message")
        token = data["msg"]
        sigt = signature.signature_export(
            groupsig.sign(token, self.memkey, self.grpkey)
        )
        res = self.sess.post(
            f"{self.url}/groupsig/revoke",
            data={"signature_token": sigt, "token": token,
                  "signature": sig}
        )
        data = decode(res, "Decoding revoke message")
        logging.info(data["msg"])
        return False if "not" in data["msg"] else True

    def status(self):
        with self.args.sig.open() as f:
            sig = f.read()
        res = self.sess.post(
            f"{self.url}/groupsig/status", data={"signature": sig}
        )
        data = decode(res, "Decoding status message")
        logging.info(data["msg"])
        return False if "not" in data["msg"] else True

    def _retrieve_grpkey(self, clients=False):
        if clients:
            res = self.sess.get(f"{self.url}/groupsig")
        else:
            res = self.sess.get(f"{self.url}/groupsig",
                                data={"revoker": 1})
        data = decode(res, "Decoding groupkey message")
        grpkey_bytes = base64.b64decode(data["msg"])
        if clients:
            self.codec = grpkey_bytes[0]
            self.grpkeyc = grpkey.grpkey_import(self.codec, data["msg"])
        else:
            self.code = grpkey_bytes[0]
            groupsig.init(self.code)
            self.grpkey = grpkey.grpkey_import(self.code, data["msg"])
        self._save_crypto()

    def _save_crypto(self):
        if self.grpkey is not None:
            with self.args.gkey.open("w") as f:
                f.write(grpkey.grpkey_export(self.grpkey))
        if self.grpkeyc is not None:
            with self.args.gkeyc.open("w") as f:
                f.write(grpkey.grpkey_export(self.grpkeyc))
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
        if self.grpkeyc is None:
            if self.args.gkeyc.is_file():
                with self.args.gkeyc.open() as f:
                    data = f.read()
                    grpkey_bytes = base64.b64decode(data)
                    self.codec = grpkey_bytes[0]
                    self.grpkeyc = grpkey.grpkey_import(
                        self.codec, data
                    )
            else:
                print(self.args.gkeyc)
                print(self.args.gkeyc.is_file())
                self._retrieve_grpkey(clients=True)
        if self.memkey is None:
            if self.args.mkey.is_file():
                with self.args.mkey.open() as f:
                    self.memkey = memkey.memkey_import(
                        self.code, f.read()
                    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Groupsig auditor client"
    )
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
    func.add_argument(
        "--verifyr",
        "-vr",
        action="store_true",
        help="Verify revoker signature",
    )
    func.add_argument(
        "--revoke", "-R", action="store_true", help="Revoke signature"
    )
    func.add_argument(
        "--status",
        "-t",
        action="store_true",
        help="Check signature status, i.e. signer has not been revoked",
    )
    parser.add_argument(
        "--host",
        "-H",
        metavar="HOST",
        default="localhost",
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
        default="gicp_api/crypto/auditors/user1.crt",
        help="Client certificate",
    )
    parser.add_argument(
        "--key",
        "-K",
        metavar="KEY",
        type=Path,
        default="gicp_api/crypto/auditors/user1.key",
        help="Client certificate key",
    )
    parser.add_argument(
        "--gkey",
        "-g",
        metavar="PATH",
        default=Path("gkey_rev"),
        type=Path,
        help="Group key file of the revoker",
    )
    parser.add_argument(
        "--gkeyc",
        "-G",
        metavar="PATH",
        default=Path("gkey"),
        type=Path,
        help="Group key file of the clients group",
    )
    parser.add_argument(
        "--mkey",
        "-m",
        metavar="PATH",
        default=Path("mkey_rev"),
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
    with Revoker(args) as revoker:
        if args.register:
            print(revoker.register())
        if args.sign:
            print(revoker.sign())
        if args.verify:
            print(revoker.verify())
        if args.verifyr:
            print(revoker.verify(True))
        if args.revoke:
            print(revoker.revoke())
        if args.status:
            print(revoker.status())


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    args = parse_args()
    main(args)
