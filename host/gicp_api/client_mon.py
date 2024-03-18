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


class Monitor:
    """
    Groupsig auditor client

    Given a signature group, this client is capable of resgistering a client,
    signing an asset, verifying asset signature, verifying (monitor) signature of an asset,
    revoking the identity linked to an asset, and checking the status of the identity linked to an asset

    Usages:

    REGISTER:
       >>> mon = Monitor('localhost', '/path/to/cert', '/path/to/key')
       >>> mon.register()
       todo: what returns?

    SIGN (requires an asset):
        >>> mon.sign('/asset/to/sign')
        todo: what returns if ok?
       {
         ...
         "form": {
           "key1": "value1",
           "key2": "value2"
         },
         ...
       }

    VERIFY (requires a signed asset):
        >>> mon.verify('/asset/to/verify')
        todo:what returns if ok?

    MONITOR VERIFICATION (requires a signed asset)
        >>> mon.verify('/asset/to/verify', monitor=True)
        todo: what returns if ok?

    REVOKE IDENTITY (requires a signature)
        >>> mon.revoke()
        todo: what returns if ok?

    CHECK IDENTITY STATUS (requires a signature)
        >>> mon.status() # mon.status(signature='/path/to/sig') ??
        todo: what returns if ok?

    """

    def __init__(self, host: str, cert: str, key: str, port: int = 5000, gkey: str = "gkey_mon",
                 gkeyc: str = "gkey", mkey: str = "mkey_mon", **kwargs):
        """
        A user-created :class:`Monitor<Monitor>` object.
        Args:
            :param host: Group signature API host/IP
            :param cert: Path to client certificate
            :param key: Path to client certificate key
            :param port: Path to group signature API port
            :param gkey: Path to monitor's group key file
            :param gkeyc: Path to group key file of the clients group
            :param mkey: Path to member key file

        """
        self.args = argparse.Namespace(
            gkey=Path(str(gkey)),
            gkeyc=Path(str(gkeyc)),
            mkey=Path(str(mkey))
        )
        self.url = f"https://{host}:{port}"
        self.sess = requests.Session()
        self.sess.verify = False
        self.sess.cert = (Path(str(cert)), Path(str(key)))
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
                    data={"phase": 1, "message": msgout, "monitor": 1},
                )
                data = decode(res, "Decoding join_1 message")
                if res.status_code == 200:
                    self.memkey = memkey.memkey_import(
                        self.code, data["msg"]
                    )
                else:
                    logging.error(data["msg"])
                    return data["msg"]
            else:
                res = self.sess.post(
                    f"{self.url}/groupsig/join",
                    data={"phase": 0, "monitor": 1}
                )
                data = decode(res, "Decoding join_0 message")
                if res.status_code == 200:
                    msg1 = message.message_from_base64(data["msg"])
                    msg2 = groupsig.join_mem(1, self.grpkey, msgin=msg1)
                    msgout = message.message_to_base64(msg2["msgout"])
                    res2 = self.sess.post(
                        f"{self.url}/groupsig/join",
                        data={"phase": 2, "message": msgout, "monitor": 1},
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

    def sign(self, asset: str, sigf: str = "sig") -> None:
        """
        Signs an asset and saves the signature in a file

        Args:
            :param asset: Path to the asset to be signed
            :param sigf: Path to file where the generated signature will be saved

        Returns: None
        """
        if self.memkey is not None and self.grpkey is not None:
            with Path(str(asset)).open("rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            sig = signature.signature_export(
                groupsig.sign(digest, self.memkey, self.grpkey)
            )
            # change self.args.sig
            with Path(str(sigf)).open("w") as f:
                f.write(sig)
            return sig
        else:
            logging.error("Missing memkey or grpkey")

    def verify(self, asset: str, sigf: str = "sig", monitor=False):
        """

        Args:
            :param asset: Path to asset file
            :param sigf: Path to signature file
            :param monitor: if True performs verification in monitor mode. 'Normal' mode otherwise

        Returns:

        """
        # I don't think we should implement verification for monitor
        # but whatever
        code = self.codec
        grpkey = self.grpkeyc
        if monitor:
            code = self.code
            grpkey = self.grpkey
        if grpkey is not None:
            with Path(str(asset)).open("rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            # change self.args.sig
            with Path(str(sigf)).open() as f:
                sig = signature.signature_import(code, f.read())
            ver = groupsig.verify(sig, digest, grpkey)
            logging.info(f"Signature verified: {ver}")
            return ver
        else:
            logging.error("Missing grpkey")

    def revoke(self, sigf: str = "sig"):
        """

        Args:
            :param sigf: Path to signature file

        Returns:

        """
        # change self.args.sig
        with Path(str(sigf)).open() as f:
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

    def status(self, sigf: str = "sig"):
        """

        Args:
            :param sigf: Path to signature file

        Returns:

        """
        # change self.args.sig
        with Path(str(sigf)).open() as f:
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
                                data={"monitor": 1})
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
        # default="gicp_api/crypto/monitors/usr1.crt",
        help="Client certificate",
    )
    parser.add_argument(
        "--key",
        "-K",
        metavar="KEY",
        type=Path,
        required=True,
        # default="gicp_api/crypto/monitors/usr1.key",
        help="Client certificate key",
    )
    parser.add_argument(
        "--gkey",
        "-g",
        metavar="PATH",
        default=Path("gkey_mon"),
        type=Path,
        help="Group key file of the monitor",
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
        default=Path("mkey_mon"),
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
    _args = parser.parse_args()
    if (_args.sign or _args.verify) and _args.asset is None:
        parser.error(
            "The --asset/-a argument is required when "
            "using --sign/-s or --verify/-v"
        )
    return _args


def main(args):
    with Monitor(**args.__dict__) as mon:
        if args.register:
            print(mon.register())
        if args.sign:
            print(mon.sign(args.asset))
        if args.verify:
            print(mon.verify(args.asset))
        if args.verifym:
            print(mon.verify(args.asset, monitor=True))
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
