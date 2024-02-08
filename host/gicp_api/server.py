import csv, os
import hashlib
import json
import logging
import ssl
import tempfile
from pathlib import Path
from uuid import uuid4

from flask import Flask, jsonify, request
from werkzeug.serving import WSGIRequestHandler


A_SCHEMES = ["mondrian"]
BASE = "./tee_demos.ke toolbox"
CMDS = {
    "anon": (
        f"{BASE} "
        "--mondrian --anonymize --input {inp} "
        "--k {k} --output {out}"
    ),
    "key": f"{BASE} --groupsig",
    "join": (
        f"{BASE} --groupsig"
        "--scheme {scheme} -j {phase} --message {msg}"
    ),
    "rev": (f"{BASE} " "--revoke {sig}"),
    "revd": (f"{BASE} " "--revoked {sig}"),
}
TOKENS = {}

app = Flask(__name__)


def temp_w(data):
    try:
        f = tempfile.NamedTemporaryFile()
        f.write(data.encode())
        f.seek(0)
        return f
    except Exception as e:
        print(f"Error creating mode:w tempfile: {str(e)}")


def temp():
    try:
        f = tempfile.NamedTemporaryFile(mode="r")
        return f
    except Exception as e:
        print(f"Error creating mode:r tempfile: {str(e)}")


def debug(cmd, msg):
    logging.debug(cmd)
    logging.info(msg)
    return cmd


def save_tokens():
    with open("tokens.json") as f:
        json.dump(TOKENS, f)


def status(sts, msg):
    if sts == "error":
        logging.error(msg)
    return jsonify({"status": sts, "msg": msg})


def clean_out(output):
    return output.replace(
        "Verifying archive integrity... "
        "All good.\nUncompressing Keystone "
        "Enclave Package\n",
        "",
    )


def tokens():
    return [client[0] for client in TOKENS.values() if not client[1]]


class PeerCertWSGIRequestHandler(WSGIRequestHandler):
    def make_environ(self):
        environ = super().make_environ()
        cert = self.connection.getpeercert()
        environ["CERT_HASH"] = hashlib.sha256(
            cert.encode()
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
    dataset = request.files["dataset"]
    if not dataset:
        return status("error", "Missing 'dataset' file")
    file_inp = temp_w(dataset.read().decode())
    k = request.form.get("k")
    k = 10 if k is None else k
    file_out = temp()
    cmd = debug(
        CMDS["anon"].format(
            input=file_inp.name, k=k, output=file_out.name
        ),
        "Anonymizing dataset",
    )
    output = clean_out(os.popen(cmd).read())
    csv_data = []
    csv_reader = csv.DictReader(file_out)
    for row in csv_reader:
        csv_data.append(row)
    return status("success", {"data": csv_data, "output": output})


@app.get("/groupsig")
def groupsig_key():
    cmd = debug(CMDS["key"], "Retrieving grpkey")
    output = clean_out(os.popen(cmd).read())
    return status("success", output)


@app.get("/groupsig/schemes")
def groupsig_schemes():
    return status("success", GS_SCHEMES)


@app.get("/groupsig/join")
def groupsig_token():
    crt_hash = request.environ.get("CERT_HASH")
    if crt_hash is not None:
        if crt_hash not in TOKENS:
            TOKENS[crt_hash] = [str(uuid4()), False]
            save_tokens()
        if TOKENS[crt_hash][1]:
            return status("error", "Already registered")
        else:
            return status("success", TOKENS[crt_hash][0])
    else:
        return status(
            "error", "Could not retrieve client certificate"
        )


@app.post("/groupsig/join/<string:token>")
def groupsig_join(token):
    if token in tokens():
        scheme = request.form.get("scheme")
        if not scheme:
            return status("error", "Missing 'scheme' in body")
        phase = request.form.get("phase")
        if not phase:
            return status("error", "Missing 'phase' in body")
        message = request.form.get("message")
        if not message:
            return status("error", "Missing 'message' in body")
        file_msg = ut.temp_w(message)
        cmd = debug(
            CMDS["join"].format(
                scheme=scheme, phase=phase, message=file_msg.name
            ),
            f"Join phase {phase} ({scheme})",
        )
        output = clean_out(os.popen(cmd).read())
        print(output)
        return status("error", output)
    else:
        return status("error", "Invalid token")


@app.post("/groupsig/revoke")
def groupsig_revoke(group):
    if group is None or not group:
        return status("error", "Missing 'group' in parameter")
    signature = request.form.get("signature")
    if not signature:
        return status("error", "Missing 'signature' in body")
    file_sig = ut.temp_w(signature)
    cmd = ut.CMD_REVOKE.format(signature=file_sig.name)
    logging.debug(cmd)
    logging.info("Revoking identity")
    output = clean_out(os.popen(cmd).read())
    status = Path(ut.FILE["status"])
    if status.is_file():
        with status.open() as f:
            result = f.read()
        if result == "1":
            return status("success", "Identity revoked")
        else:
            return status("success", "Identity could not be revoked")
    return status("error", output)


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    tokens = Path("tokens.json")
    if tokens.is_file():
        with tokens.open() as f:
            TOKENS = json.load(f)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(
        certfile="server.crt", keyfile="server.key"
    )
    context.load_verify_locations(cafile="ca/ca.crt")
    app.run(
        host="0.0.0.0",
        ssl_context=("cert.crt", "cert.key"),
        request_handler=PeerCertWSGIRequestHandler,
    )
