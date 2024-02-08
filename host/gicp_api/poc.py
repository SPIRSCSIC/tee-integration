import logging
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = "https://localhost:5000"


def get(url, name, kwargs=None):
    logging.debug(f"Testing GET ({name})")
    try:
        if kwargs is not None:
            response = requests.get(url, verify=False, **kwargs)
        else:
            response = requests.get(url, verify=False)
        return response.json()
    except requests.exceptions.RequestException as e:
        print("Request error:", e)


def post(url, name, kwargs=None):
    logging.debug(f"Testing POST ({name})")
    try:
        if kwargs is not None:
            response = requests.post(url, verify=False, **kwargs)
        else:
            response = requests.post(url, verify=False)
        return response.json()
    except requests.exceptions.RequestException as e:
        print("Request error:", e)


def anonymization_schemes():
    return get(
        f"{URL}/anonymization/schemes", "anonymization/schemes"
    )


def anonymization_anonymize():
    files = {
        "dataset": open("modules/mondrian/datasets/tee.csv", "rb")
    }
    return post(
        f"{URL}/anonymization/schemes/mondrian",
        "anonymization/schemes",
        dict(files=files, data={"k": 10}),
    )


def groupsig_groups():
    return get(f"{URL}/groupsig/groups", "groupsig/groups")


def groupsig_group_new():
    return post(
        f"{URL}/groupsig/groups",
        "groupsig/groups",
        dict(data={"group": "new"}),
    )


def groupsig_member_register():
    return post(f"{URL}/groupsig/groups/def", "groupsig/groups/def")


def groupsig_sign(msg, key):
    return post(
        f"{URL}/groupsig/groups/def/sign",
        "groupsig/groups/def/sign",
        dict(data={"message": msg, "key": key}),
    )


def groupsig_verify(msg, sig):
    return post(
        f"{URL}/groupsig/groups/def/verify",
        "groupsig/groups/def/verify",
        dict(data={"message": msg, "signature": sig}),
    )


def groupsig_open(sig):
    return get(
        f"{URL}/groupsig/groups/def/open",
        "groupsig/groups/def/open",
        dict(data={"signature": sig}),
    )


def groupsig_revoke(sig):
    return post(
        f"{URL}/groupsig/groups/def/revoke",
        "groupsig/groups/def/revoke",
        dict(data={"signature": sig}),
    )


def groupsig_revoked(sig):
    return get(
        f"{URL}/groupsig/groups/def/revoked",
        "groupsig/groups/def/revoked",
        dict(data={"signature": sig}),
    )


def mondrian():
    resp = anonymization_schemes()
    logging.info(
        f"GET anonymization/schemes ({resp['status']}): "
        f"{resp['msg']}"
    )
    resp = anonymization_anonymize()
    logging.info(
        f"POST anonymization/schemes ({resp['status']}): "
        f"{resp['msg']}"
    )


def groupsig():
    # resp = groupsig_group_new()
    # logging.info(f"POST groupsig/groups ({resp['status']}): "
    #              f"{resp['msg']}")
    # resp = groupsig_group_new()
    # logging.info(f"POST groupsig/groups ({resp['status']}): "
    #              f"{resp['msg']}")
    resp = groupsig_groups()
    logging.info(
        f"GET groupsig/groups ({resp['status']}): " f"{resp['msg']}"
    )
    msg1 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    msg2 = "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7"
    resp = groupsig_member_register()
    logging.info(
        f"POST groupsig/groups/def ({resp['status']}): "
        f"{resp['msg']}"
    )
    key1 = resp["msg"]
    resp = groupsig_member_register()
    logging.info(
        f"POST groupsig/groups/def ({resp['status']}): "
        f"{resp['msg']}"
    )
    key2 = resp["msg"]
    resp = groupsig_sign(msg1, key1)
    logging.info(
        f"POST groupsig/groups/def/sign ({resp['status']}): "
        f"{resp['msg']}"
    )
    sig1 = resp["msg"]
    resp = groupsig_sign(msg2, key2)
    logging.info(
        f"POST groupsig/groups/def/sign ({resp['status']}): "
        f"{resp['msg']}"
    )
    sig2 = resp["msg"]
    resp = groupsig_verify(msg1, sig1)
    logging.info(
        f"POST groupsig/groups/def/verify ({resp['status']}): "
        f"{resp['msg']}"
    )
    resp = groupsig_verify(msg2, sig1)
    logging.info(
        f"POST groupsig/groups/def/verify ({resp['status']}): "
        f"{resp['msg']}"
    )
    resp = groupsig_open(sig1)
    logging.info(
        f"GET groupsig/groups/def/open ({resp['status']}): "
        f"{resp['msg']}"
    )
    resp = groupsig_revoke(sig1)
    logging.info(
        f"POST groupsig/groups/def/revoke ({resp['status']}): "
        f"{resp['msg']}"
    )
    resp = groupsig_revoked(sig1)
    logging.info(
        f"GET groupsig/groups/def/revoked ({resp['status']}): "
        f"{resp['msg']}"
    )
    resp = groupsig_revoked(sig2)
    logging.info(
        f"GET groupsig/groups/def/revoked ({resp['status']}): "
        f"{resp['msg']}"
    )


def governance_scheme():
    def step1(exe):
        logging.info("## Dev: Getting group signature credential")
        resp = groupsig_member_register()
        logging.info(
            f"POST groupsig/groups/def ({resp['status']}): "
            f"{resp['msg']}"
        )
        devkey = resp["msg"]
        logging.info("## Dev: Signing exe (hash)")
        resp = groupsig_sign(exe, devkey)
        logging.debug(
            f"POST groupsig/groups/def/sign ({resp['status']}): "
            f"{resp['msg']}"
        )
        s1 = resp["msg"]
        return s1

    def step2(s1):
        logging.info("## Dev->DLT: Inserting signature (DevBlock)")
        # TODO: For the time being, storing and retrieving
        # from a file will be used to show a PoC
        devblock = Path("devblock.txt")
        with devblock.open("w") as f:
            f.write(s1)
        # Upload the name of the file. It should be the URI
        # where the signature is stored
        logging.info("## Dev->Witness: Sending DevBlockID")
        devblockid = Path("devblockid.txt")
        with devblockid.open("w") as f:
            f.write(str(devblock))
        return devblockid

    def step3456(exe, devblockid):
        logging.info(
            "## Witness->DLT: Retrieving signature (DevBlock)"
        )
        with devblockid.open() as f:
            devblock_f = f.read()
        devblock = Path(devblock_f)
        with devblock.open() as f:
            s1 = f.read()
        resp = groupsig_verify(exe, s1)
        logging.debug(
            f"POST groupsig/groups/def/verify ({resp['status']}): "
            f"{resp['msg']}"
        )
        if "does not" not in resp["msg"]:
            logging.info(
                "## Witness: Getting group signature credential"
            )
            resp = groupsig_member_register()
            logging.info(
                f"POST groupsig/groups/def ({resp['status']}): "
                f"{resp['msg']}"
            )
            audkey = resp["msg"]

            logging.info("## Witness: Signing audit")
            resp = groupsig_sign(exe, audkey)
            logging.info(
                f"POST groupsig/groups/def/sign ({resp['status']}): "
                f"{resp['msg']}"
            )
            s2 = resp["msg"]
            logging.info(
                "## Witness->DLT: Inserting signature (AudBlock)"
            )
            audblock = Path("audblock.txt")
            with audblock.open("w") as f:
                f.write(s2)
            logging.info("## Witness->Dev: Sending AudBlockID")
            audblockid = Path("audblockid.txt")
            with audblockid.open("w") as f:
                f.write(str(audblock))
            return audblockid

    def step7(exe, devblockid, audblockid):
        logging.info(
            "## Dev->Repository: "
            "Uploading exe, DevBlockId, AudBlockID"
        )
        upload = Path("upload.txt")
        with upload.open("w") as f:
            f.write(f"{exe}\n")
            f.write(f"{str(devblockid)}\n")
            f.write(f"{str(audblockid)}\n")
        return upload

    def step8910(upload):
        logging.info(
            "## User->DLT: Requesting update: "
            "exe, DevBlockID, AudBlockID"
        )
        with upload.open() as f:
            exe, devblockid_f, audblockid_f = [
                line.strip() for line in f.readlines()
            ]
        logging.info(
            "## User->DLT: Retrieving DevBlockID, AudBlockID"
        )
        devblockid = Path(devblockid_f)
        audblockid = Path(audblockid_f)
        with devblockid.open() as f:
            devblock_f = f.read()
        devblock = Path(devblock_f)
        with audblockid.open() as f:
            audblock_f = f.read()
        audblock = Path(audblock_f)
        with devblock.open() as f:
            s1 = f.read()
        with audblock.open() as f:
            s2 = f.read()
        resp = groupsig_verify(exe, s1)
        logging.info(
            f"POST groupsig/groups/def/verify ({resp['status']}): "
            f"{resp['msg']}"
        )
        logging.info(resp["msg"])
        resp = groupsig_verify(exe, s2)
        logging.info(
            f"POST groupsig/groups/def/verify ({resp['status']}): "
            f"{resp['msg']}"
        )
        logging.info(resp["msg"])

    exe = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    s1 = step1(exe)
    devblockid = step2(s1)
    audblockid = step3456(exe, devblockid)
    upload = step7(exe, devblockid, audblockid)
    step8910(upload)


def clean():
    Path("upload.txt").unlink()
    Path("devblock.txt").unlink()
    Path("audblock.txt").unlink()
    Path("devblockid.txt").unlink()
    Path("audblockid.txt").unlink()


def main():
    # mondrian()
    # groupsig()
    governance_scheme()
    clean()


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    main()
