import argparse
import csv
import hashlib
import json
import logging
import re
import ssl
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

from flask import Flask, jsonify, request
from werkzeug.exceptions import BadRequestKeyError
from werkzeug.serving import WSGIRequestHandler


A_SCHEMES = ["mondrian"]
BS = ["./gdemos.ke"]
FINAL_PATH = "/root/.last"
OK = re.compile(rb"Package\n(.*)", re.S)
ERR = re.compile(rb"(.*?)\[host\]", re.S)
TOKENS = {"producers": {}, "monitors": {}}
NONCES = {}
GRPKEY = {"producers": None}

app = Flask(__name__)


def temp_w(data):
    try:
        f = tempfile.NamedTemporaryFile()
        f.write(data.encode())
        f.seek(0)
        return f
    except Exception as e:
        logging.error(f"Creating mode:w tempfile: {str(e)}")


def temp():
    try:
        f = tempfile.NamedTemporaryFile(mode="r")
        return f
    except Exception as e:
        logging.error(f"Creating mode:r tempfile: {str(e)}")


def run(cmd, text):
    logging.info(" ".join(cmd))
    logging.info(text)
    out = subprocess.run(cmd, capture_output=True)
    logging.info(f"stdout: {out.stdout}\n\nstderr: {out.stderr}")
    err = False
    if out.stderr:
        msg = ERR.search(out.stderr).group(1)
        err = True
    else:
        msg = OK.search(out.stdout).group(1)
    msg = msg.decode().strip()
    logging.info(msg)
    return msg, err


def save_tokens():
    with open("tokens.json", "w") as f:
        json.dump(TOKENS, f)

def save_nonces():
    with open("nonces.json", "w") as f:
        json.dump(NONCES, f)


def status(sts, msg):
    code = 200
    if sts == "error":
        logging.error(msg)
        code = 400
    return jsonify({"msg": msg}), code


class PeerCertWSGIRequestHandler(WSGIRequestHandler):
    def make_environ(self):
        environ = super().make_environ()
        cert = self.connection.getpeercert()
        environ["CERT_HASH"] = hashlib.sha256(
            str(cert).encode()
        ).hexdigest()
        return environ


@app.get("/anonymization/schemes")
def anonymization_schemes():
    return status("success", A_SCHEMES)


@app.post("/anonymization/schemes/<string:scheme>")
def anonymization_anonymize(scheme):
    if scheme not in A_SCHEMES:
        return status(
            "error", f"Unsuported anonymization scheme: {scheme}"
        )
    try:
        dataset = request.files["dataset"]
    except BadRequestKeyError:
        return status("error", "Missing 'dataset' file")
    file_inp = temp_w(dataset.read().decode())
    mode = request.form.get("mode")
    relaxed = ""
    if mode is not None and mode == "relaxed":
        relaxed = "--relaxed"
    k = request.form.get("k")
    k = 10 if k is None else k
    file_out = temp()
    cmd_args = [
        "mondrian",
        "--anonymize",
        "--input",
        f"{file_inp.name}",
        "--k",
        f"{k}",
        "--output",
        f"{file_out.name}",
    ]
    if relaxed:
        cmd_args.append(relaxed)
    output, err = run(BS + cmd_args, "Anonymizing dataset")
    if err:
        return status("error", output)
    csv_data = []
    csv_reader = csv.reader(file_out)
    for row in csv_reader:
        csv_data.append(row)
    return status("success", {"data": csv_data, "output": output})


@app.get("/groupsig")
def groupsig_key():
    cmd_args = ["groupsig"]
    grpkey_k = "producers"
    monitor = request.form.get("monitor") or request.args.get("monitor")
    if monitor is not None and monitor == "1":
        cmd_args.extend(["--affix", ARGS.affix])
        grpkey_k = ARGS.affix
        if grpkey_k not in GRPKEY:
            GRPKEY[grpkey_k] = None
    if GRPKEY[grpkey_k] is None:
        output, err = run(BS + cmd_args, "Retrieving grpkey")
        if err:
            return status("error", output)
        GRPKEY[grpkey_k] = output
    return status("success", GRPKEY[grpkey_k])


@app.post("/groupsig/join")
def groupsig_join():
    tokens = TOKENS["producers"]
    monitor = request.form.get("monitor")
    is_monitor = False
    if monitor is not None and monitor == "1":
        tokens = TOKENS["monitors"]
        is_monitor = True
    crt_hash = request.environ.get("CERT_HASH")
    if crt_hash not in tokens:
        tokens[crt_hash] = False
        save_tokens()
    if tokens[crt_hash]:
        return status("error", "Already registered")
    else:
        phase = request.form.get("phase")
        if not phase:
            return status("error", "Missing 'phase' in body")
        if int(phase):
            message = request.form.get("message")
            if not message:
                return status("error", "Missing 'message' in body")
            file_msg = temp_w(message)
        else:
            file_msg = temp()
        cmd_args = [
            "groupsig",
            "--join",
            f"{phase}",
            "--message",
            f"{file_msg.name}",
        ]
        if is_monitor:
            cmd_args.extend(["--affix", ARGS.affix])
        output, err = run(
            BS + cmd_args,
            f"Join phase {phase}",
        )
        if err:
            return status("error", output)
        if not output:
            msg = file_msg.read()
            if isinstance(msg, (bytes, bytearray)):
                msg = msg.decode()
        else:
            msg = output
        final = Path(FINAL_PATH)
        if final.exists():
            tokens[crt_hash] = True
            save_tokens()
            # print(f"found {FINAL_PATH}, removing!")
            final.unlink()
        return status("success", msg)


@app.get("/groupsig/revoke")
def groupsig_revoke_nonce():
    token = uuid4()
    NONCES[str(token)] = False
    save_nonces()
    return status("success", token)


@app.post("/groupsig/revoke")
def groupsig_revoke():
    token = request.form.get("token")
    if not token:
        return status("error", "Missing 'token' in body")
    if token in NONCES and not NONCES[token]:
        signaturet = request.form.get("signature_token")
        if not signaturet:
            return status("error", "Missing 'signature_token' in body")
        signature = request.form.get("signature")
        if not signature:
            return status("error", "Missing 'signature' in body")
        file_tok = temp_w(token)
        file_sigt = temp_w(signaturet)
        output, err = run(
            BS
            + [
                "groupsig",
                "--verify",
                f"{file_sigt.name}",
                "--asset",
                f"{file_tok.name}",
                "--affix",
                ARGS.affix,
            ],
            "Verifying signature",
        )
        if err:
            return status("error", output)
        if output == "1":
            file_sig = temp_w(signature)
            output, err = run(
                BS
                + [
                    "groupsig",
                    "--revoke",
                    f"{file_sig.name}",
                ],
                "Revoking identity",
            )
            if err:
                return status("error", output)
            if output == "1":
                NONCES[token] = True
                save_nonces()
                return status("success", "Identity revoked")
            else:
                return status("success", output)
        else:
            return status("error", "Invalid signature")
    else:
        return status("error", "Invalid token or already used")


@app.post("/groupsig/status")
def groupsig_status():
    signature = request.form.get("signature")
    if not signature:
        return status("error", "Missing 'signature' in body")
    file_sig = temp_w(signature)
    output, err = run(
        BS + ["groupsig", "--status", f"{file_sig.name}"],
        "Checking signature status",
    )
    if err:
        return status("error", output)
    if output == "1":
        return status("success", "Identity revoked")
    else:
        return status("success", "Identity not revoked")


def parse_args():
    parser = argparse.ArgumentParser(description="GroupSig API")
    parser.add_argument(
        "--host",
        "-H",
        metavar="HOST",
        default="0.0.0.0",
        help="Host to listen on",
    )
    parser.add_argument(
        "--port",
        "-P",
        metavar="PORT",
        type=int,
        default=5000,
        help="Port to listen on",
    )
    parser.add_argument(
        "--cert",
        "-C",
        metavar="CERT",
        required=True,
        # default="crypto/gms/usr1.crt",
        help="Server certificate",
    )
    parser.add_argument(
        "--key",
        "-K",
        metavar="KEY",
        required=True,
        # default="crypto/gms/usr1.key",
        help="Server certificate key",
    )
    parser.add_argument(
        "--chain",
        "-c",
        metavar="CHAIN",
        required=True,
        # default="gicp_api/crypto/chain.pem",
        help="Certificate chain to validate clients",
    )
    parser.add_argument(
        "--tokens",
        "-t",
        metavar="TOKEN",
        default="gicp_api/tokens.json",
        help="Tokens file",
    )
    parser.add_argument(
        "--affix",
        "-a",
        metavar="AFFIX",
        default="_mon",
        help="Affix for monitor crypto material",
    )
    return parser.parse_args()


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    ARGS = parse_args()
    tokens_f = Path("tokens.json")
    if tokens_f.is_file():
        with tokens_f.open() as f:
            TOKENS = json.load(f)
    nonces_f = Path("nonces.json")
    if nonces_f.is_file():
        with nonces_f.open() as f:
            NONCES = json.load(f)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=ARGS.cert, keyfile=ARGS.key)
    context.load_verify_locations(ARGS.chain)
    app.run(
        host=ARGS.host,
        ssl_context=context,
        request_handler=PeerCertWSGIRequestHandler,
    )
