import csv, os
import hashlib
import json
import logging
import ssl
import tempfile
from pathlib import Path
from uuid import uuid4
import subprocess
import argparse
import re

from flask import Flask, jsonify, request
from werkzeug.serving import WSGIRequestHandler


A_SCHEMES = ["mondrian"]
GS_SCHEMES = ["ps16", "kty04", "gl19"]
BS = ["./gdemos.ke", "toolbox"]
OK = re.compile(rb"Package\n(.*)", re.S)
ERR = re.compile(rb"(.*?)\[host\]", re.S)
TOKENS = {}
GRPKEY = None

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
    if out.stderr:
        msg = ERR.search(out.stderr).group(1)
    else:
        msg = OK.search(out.stdout).group(1)
    msg = msg.decode().strip()
    logging.info(msg)
    return msg


def save_tokens():
    with open("tokens.json", "w") as f:
        json.dump(TOKENS, f)


def status(sts, msg):
    if sts == "error":
        logging.error(msg)
    return jsonify({"status": sts, "msg": msg})


def tokens():
    return [client[0] for client in TOKENS.values() if not client[1]]


class PeerCertWSGIRequestHandler(WSGIRequestHandler):
    def make_environ(self):
        environ = super().make_environ()
        cert = self.connection.getpeercert()
        environ["CERT_HASH"] = hashlib.sha256(
            str(cert).encode()).hexdigest()
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
    dataset = request.files["dataset"]
    if not dataset:
        return status("error", "Missing 'dataset' file")
    file_inp = temp_w(dataset.read().decode())
    k = request.form.get("k")
    k = 10 if k is None else k
    file_out = temp()
    output = run(
        BS + [
            "--mondrian",
            "--anonymize",
            "--input",
            f"{file_inp.name}",
            "--k",
            f"{k}",
            "--output",
            f"{file_out.name}",
        ],
        "Anonymizing dataset",
    )
    csv_data = []
    csv_reader = csv.DictReader(file_out)
    for row in csv_reader:
        csv_data.append(row)
    return status("success", {"data": csv_data, "output": output})


@app.get("/groupsig")
def groupsig_key():
    global GRPKEY
    if GRPKEY is None:
        output = run(BS + ["--groupsig"], "Retrieving grpkey")
        GRPKEY = output
    return status("success", GRPKEY)


@app.get("/groupsig/schemes")
def groupsig_schemes():
    return status("success", GS_SCHEMES)


@app.post("/groupsig/join")
def groupsig_join():
    crt_hash = request.environ.get("CERT_HASH")
    if crt_hash not in TOKENS:
        TOKENS[crt_hash] = False
        save_tokens()
    if TOKENS[crt_hash]:
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
        output = run(
            BS + [
                "--groupsig",
                "--join",
                f"{phase}",
                "--message",
                f"{file_msg.name}"
            ],
            f"Join phase {phase}",
        )
        if not output:
            msg = file_msg.read()
            if isinstance(msg, (bytes, bytearray)):
                msg = msg.decode()
            if int(phase) in [1, 2]:
                TOKENS[crt_hash] = True
                save_tokens()
        else:
            msg = output
        return status("success", msg)


@app.post("/groupsig/revoke")
def groupsig_revoke():
    signature = request.form.get("signature")
    if not signature:
        return status("error", "Missing 'signature' in body")
    file_sig = temp_w(signature)
    output = run(
        BS + ["--groupsig",
              "--revoke",
              f"{file_sig.name}"],
        "Revoking identity",
    )
    if output == "1":
        return status("success", "Identity revoked")
    else:
        return status("success", "Identity could not be revoked")


@app.post("/groupsig/revoked")
def groupsig_revoked():
    signature = request.form.get("signature")
    if not signature:
        return status("error", "Missing 'signature' in body")
    file_sig = temp_w(signature)
    output = run(
        BS + ["--groupsig",
              "--revoked",
              f"{file_sig.name}"],
        "Checking signature status",
    )
    if output == "1":
        return status("success", "Identity revoked")
    else:
        return status("success", "Identity not revoked")


def parse_args():
    parser = argparse.ArgumentParser(description="GroupSig API")
    parser.add_argument(
        "--host", "-H",
        metavar="HOST",
        default="0.0.0.0",
        help="Host to listen on"
    )
    parser.add_argument(
        "--port", "-P",
        metavar="PORT",
        type=int,
        default=5000,
        help="Port to listen on",
    )
    parser.add_argument(
        "--cert", "-C",
        metavar="CERT",
        default="gicp_api/crypto/gms/user1.crt",
        help="Server certificate"
    )
    parser.add_argument(
        "--key", "-K",
        metavar="KEY",
        default="gicp_api/crypto/gms/user1.key",
        help="Server certificate key"
    )
    parser.add_argument(
        "--chain", "-c",
        metavar="CHAIN",
        default="gicp_api/crypto/auditors/ca.crt",
        help="Certificate chain to validate clients"
    )
    parser.add_argument(
        "--tokens", "-t",
        metavar="TOKEN",
        default="gicp_api/tokens.json",
        help="Tokens file"
    )
    return parser.parse_args()


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    args = parse_args()
    tokens_f = Path("tokens.json")
    if tokens_f.is_file():
        with tokens_f.open() as f:
            TOKENS = json.load(f)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    context.load_verify_locations(args.chain)
    app.run(
        host=args.host,
        ssl_context=context,
        request_handler=PeerCertWSGIRequestHandler,
    )
