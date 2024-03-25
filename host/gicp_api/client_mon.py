import argparse
import base64
import hashlib
import logging
import sys
from typing import Any
from pathlib import Path

import requests
import urllib3
from _groupsig import ffi
from pygroupsig import (
    groupsig,
    grpkey,
    memkey,
    message,
    signature,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _decode(resp, msg) -> dict:
    try:
        return resp.json()
    except requests.JSONDecodeError:
        logging.error(msg)
        sys.exit(1)


def _groupsig_join_mgr(phase, session, url, msg=None, decoded=True) -> tuple[Any, bool]:
    data = {"phase": phase, "monitor": 1}
    if msg is not None:
        msgout = message.message_to_base64(msg["msgout"])
        data = {"phase": phase, "message": msgout, "monitor": 1}
    res = session.post(f"{url}/groupsig/join", data=data)
    data = _decode(res, f"Decoding join_mgr_{phase}")
    if res.status_code == 200:
        if decoded:
            return message.message_from_base64(data["msg"]), False
        else:
            return data["msg"], False
    else:
        logging.error(data["msg"])
        return data["msg"], True


def _join(start, steps, gkey, session, url) -> tuple[Any, bool]:
    mem_m = None
    mgr_m = ffi.NULL
    mekey = ffi.NULL
    for phase in range(steps + 1):
        if (not start and not phase % 2) or (start and phase % 2):
            mgr_m, err = _groupsig_join_mgr(phase, session, url, mem_m)
            if err: return mgr_m, err
        else:
            mem_m = groupsig.join_mem(phase, gkey, msgin=mgr_m, memkey=mekey)
            mekey = mem_m["memkey"]
    return mekey, False


class Monitor:
    """
    Group signatures client: Implements the functions for registration,
    signing, verification of signatures, verification of signatures issued by the monitor,
    revocation of identity linked to a signature and checking the status of an identity linked to signature
    within a group signature.

    Usages:

    REGISTER:
       >>> mon = Monitor('localhost', '/path/to/cert', '/path/to/key')
       >>> mon.register()
       AgIgAAAAUvOk...8Su7gfJ

    SIGN (requires an asset):
       >>> mon.sign('/asset/to/sign')
       AjAAAAAKWU1...bDiMIUr
       >>> # mon.sign('/asset/to/sign', '/output/signature')

    VERIFY (requires a signature):
       >>> mon.verify('/asset/to/verify')
       True
       >>> # mon.verify('/asset/to/verify', '/signature/to/verify')

    VERIFY MONITOR SIGATURE (requires a signature):
       >>> mon.verify('/asset/to/verify', monitor=True)
       True
       >>> # mon.verify('/asset/to/verify', '/signature/to/verify', monitor=True)

    REVOKE (requires a signature):
       >>> mon.revoke()
       True
       >>> # mon.revoke('/input/signature')

    CHECK IDENTITY STATUS (requires a signature)
       >>> mon.status()
       True
       >>> # mon.status('/input/signature')

    """

    def __init__(self, host: str, cert: str, key: str,
                 port: int = 5000, gkey: str = "gkey_mon",
                 mkey: str = "mkey_mon",
                 gkeyc: str = "gkey", **kwargs):
        """
        :param host: Group signature API host/IP
        :type host: str
        :param cert: Path to client certificate
        :type cert: str
        :param key: Path to client key
        :type key: str
        :param port: Group signature API port, defaults to 5000
        :type port: int, optional
        :param gkey: Path to group key file, defaults to "gkey"
        :type gkey: str, optional
        :param mkey: Path to member key file, defaults to "mkey"
        :type mkey: str, optional
        """
        self.url = f"https://{host}:{port}"
        self.gkey = Path(gkey)
        self.mkey = Path(mkey)
        self.gkeyc = Path(gkeyc)
        self.sess = requests.Session()
        self.sess.verify = False
        self.sess.cert = (cert, key)
        self.code = None
        self.grpkey = None
        self.memkey = None
        self.codec = None
        self.grpkeyc = None
        self._load_crypto()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.code is not None:
            groupsig.clear(self.code)

    def register(self) -> str | None:
        """
        Registers an identity in the group

        :return: Member key encoded in base64 or None
        :rtype: str or None
        """
        if self.memkey is None and self.grpkey is not None:
            seq = groupsig.get_joinseq(self.code)
            start = groupsig.get_joinstart(self.code)
            if start == 1 and seq == 1: # kty04
                mem_m = groupsig.join_mem(0, self.grpkey)
                mgr_m, err = _groupsig_join_mgr(
                    1, self.sess, self.url, mem_m, decoded=False)
                if err: return mgr_m
                self.memkey = memkey.memkey_import(
                    self.code, mgr_m)
            else:
                self.memkey, err = _join(
                    start, seq, self.grpkey, self.sess, self.url)
                if err: return self.memkey
            self._save_crypto()
            return memkey.memkey_export(self.memkey)
        else:
            logging.error("Already registered")

    def sign(self, asset: str, sig: str = "sig") -> str | None:
        """
        Signs an asset and stores the signature in a file

        :param asset: Path to the asset to be signed
        :type asset: str
        :param sig: Path to store the signature, defaults to "sig"
        :type sig: str, optional

        :return: Signature encoded in base64 or None
        :rtype: str | None
        """
        if self.memkey is not None and self.grpkey is not None:
            with Path(asset).open("rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            sig64 = signature.signature_export(
                groupsig.sign(digest, self.memkey, self.grpkey)
            )
            with Path(sig).open("w") as f:
                f.write(sig64)
            return sig64
        else:
            logging.error("Missing memkey or grpkey")

    def verify(self, asset: str, sig: str = "sig", monitor=False) -> bool | None:
        """
        Verifies an asset against its signature

        :param asset: Path to the signed asset
        :type asset: str
        :param sig: Path to the signature, defaults to "sig"
        :type sig: str, optional
        :param monitor: Boolean indicating if the signature was issued by a monitor. defaults to False
        :type monitor: bool, optional

        :return: A boolean indicating the verification status or None
        :rtype: bool | None
        """
        # I don't think we should implement verification for monitor but whatever
        code = self.codec
        gkey = self.grpkeyc
        if monitor:
            code = self.code
            gkey = self.grpkey
        if gkey is not None:
            with Path(asset).open("rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            with Path(sig).open() as f:
                sigobj = signature.signature_import(code, f.read())
            ver = groupsig.verify(sigobj, digest, gkey)
            logging.info(f"Signature verified: {ver}")
            return ver
        else:
            logging.error("Missing grpkey")

    def revoke(self, sig: str = "sig") -> bool | None:
        """
        Revokes the identity linked to a signature

        :param sig: Path to the signature, defaults to "sig"
        :type sig: str, optional

        :return: A boolean indicating the status of the revocation call or None
        :rtype: bool | None
        """
        # change self.args.sig
        if self.memkey is not None and self.grpkey is not None:
            res = self.sess.get(f"{self.url}/groupsig/revoke")
            data = _decode(res, "Decoding revoke token message")
            token = data["msg"]
            sigt = signature.signature_export(
                groupsig.sign(token, self.memkey, self.grpkey)
            )
            with Path(sig).open() as f:
                sig64 = f.read()
            res2 = self.sess.post(
                f"{self.url}/groupsig/revoke",
                data={"signature_token": sigt, "token": token,
                      "signature": sig64}
            )
            data = _decode(res2, "Decoding revoke message")
            logging.info(data["msg"])
            if "Error" in data["msg"]:
                return
            return False if "not" in data["msg"] else True
        else:
            logging.error("Missing memkey or grpkey")

    def status(self, sig: str = "sig") -> bool | None:
        """
        Retrieves the status of the identity linked to a signature

        :param sig: Path to the signature, defaults to "sig"
        :type sig: str, optional

        :return: A boolean indicating the identity revocation status or None
        :rtype: bool | None
        """

        with Path(sig).open() as f:
            sig64 = f.read()
        res = self.sess.post(
            f"{self.url}/groupsig/status",
            data={"signature": sig64}
        )
        data = _decode(res, "Decoding status message")
        logging.info(data["msg"])
        if "Error" in data["msg"]:
            return
        return False if "not" in data["msg"] else True

    def _retrieve_grpkey(self, clients=False) -> None:
        if clients:
            res = self.sess.get(f"{self.url}/groupsig")
        else:
            res = self.sess.get(f"{self.url}/groupsig",
                                data={"monitor": 1})
        data = _decode(res, "Decoding groupkey message")
        if res.status_code == 200:
            grpkey_bytes = base64.b64decode(data["msg"])
            if clients:
                self.codec = grpkey_bytes[0]
                self.grpkeyc = grpkey.grpkey_import(
                    self.codec, data["msg"])
            else:
                self.code = grpkey_bytes[0]
                groupsig.init(self.code)
                self.grpkey = grpkey.grpkey_import(
                    self.code, data["msg"])
            self._save_crypto()
        else:
            logging.error(data["msg"])
            sys.exit(1)

    def _save_crypto(self) -> None:
        if self.grpkey is not None:
            with self.gkey.open("w") as f:
                f.write(grpkey.grpkey_export(self.grpkey))
        if self.grpkeyc is not None:
            with self.gkeyc.open("w") as f:
                f.write(grpkey.grpkey_export(self.grpkeyc))
        if self.memkey is not None:
            with self.mkey.open("w") as f:
                f.write(memkey.memkey_export(self.memkey))

    def _load_grpkey(self, clients=False) -> None:
        gkey = self.gkey
        if clients:
            gkey = self.gkeyc
        if gkey.is_file():
            with gkey.open() as f:
                data = f.read()
                grpkey_bytes = base64.b64decode(data)
                if clients:
                    self.codec = grpkey_bytes[0]
                    self.grpkeyc = grpkey.grpkey_import(
                        self.codec, data
                    )
                else:
                    self.code = grpkey_bytes[0]
                    groupsig.init(self.code)
                    self.grpkey = grpkey.grpkey_import(
                        self.code, data)
        else:
            self._retrieve_grpkey(clients=clients)

    def _load_crypto(self) -> None:
        if self.grpkey is None:
            self._load_grpkey()
        if self.grpkeyc is None:
            self._load_grpkey(clients=True)
        if self.memkey is None:
            if self.mkey.is_file():
                with self.mkey.open() as f:
                    self.memkey = memkey.memkey_import(
                        self.code, f.read()
                    )


def _parse_args():
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
        "--verifym",
        "-vm",
        action="store_true",
        help="Verify monitor signature",
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
        # required=True,
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
        metavar="PATH",
        # required=True,
        default="../crypto/monitors/usr1.crt",
        help="Client certificate",
    )
    parser.add_argument(
        "--key",
        "-K",
        metavar="PATH",
        # required=True,
        default="../crypto/monitors/usr1.key",
        help="Client certificate key",
    )
    parser.add_argument(
        "--gkey",
        "-g",
        metavar="PATH",
        default="gkey_mon",
        help="Group key file",
    )
    parser.add_argument(
        "--mkey",
        "-m",
        metavar="PATH",
        default="mkey_mon",
        help="Member key file",
    )
    parser.add_argument(
        "--gkeyc",
        "-G",
        metavar="PATH",
        default="gkey",
        help="Group key file (clients group)",
    )
    parser.add_argument(
        "--sig",
        "-S",
        metavar="PATH",
        default="sig",
        help="Signature file",
    )
    parser.add_argument(
        "--asset", "-a", metavar="PATH",
        help="Asset file"
    )
    args = parser.parse_args()
    if (args.sign or args.verify) and args.asset is None:
        parser.error(
            "The --asset/-a argument is required when "
            "using --sign/-s or --verify/-v"
        )
    return args


def main(args):
    with Monitor(**args.__dict__) as mon:
        if args.register:
            print(mon.register())
        if args.sign:
            print(mon.sign(args.asset, sig=args.sig))
        if args.verify:
            print(mon.verify(args.asset, sig=args.sig))
        if args.verifym:
            print(mon.verify(args.asset, sig=args.sig, monitor=True))
        if args.revoke:
            print(mon.revoke(args.sig))
        if args.status:
            print(mon.status(args.sig))


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    main(_parse_args())
