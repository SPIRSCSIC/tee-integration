import base64
import subprocess
from pathlib import Path

import pytest
import requests.exceptions
from client import Producer
from client_mon import Monitor

# ============= A U X =============================================

# Ignore urllib3 unverified HTTPS warnings
pytestmark = pytest.mark.filterwarnings(
    "ignore:Unverified HTTPS request"
)


def is_base64(s):
    try:
        print(f"original: {s}")
        # Attempt base64 decoding, encode again and compare against original input
        return (
            base64.b64encode(base64.b64decode(str(s))) == s.encode()
        )
    except Exception:
        return False


# ============= F I X T U R E S ===================================
CWD = Path(__file__).parents[2]
CRP = CWD / "crypto"
PCRT = CRP / "producers/usr1.crt"
PKEY = CRP / "producers/usr1.key"
PCSR = CRP / "producers/usr1.csr"
MCRT = CRP / "monitors/usr1.crt"
MKEY = CRP / "monitors/usr1.key"
MCSR = CRP / "monitors/usr1.csr"

test_files = [
    "gkey",
    "gkey_mon",
    "mkey",
    "mkey_mon",
    "sig",
    "sig_mon ",
    "anasset",
]


# TODO: test with self-signed cert, so server should return sslError unknown CA
# Until then, this fixture is useless
@pytest.fixture(scope="session")
def setup_keys():
    _CRP = "./crypto"
    _PCRT = f"{_CRP}/producers/usr1.crt"
    _PKEY = f"{_CRP}/producers/usr1.key"
    _PCSR = f"{_CRP}/producers/usr1.csr"
    _MCRT = f"{_CRP}/monitors/usr1.crt"
    _MKEY = f"{_CRP}/monitors/usr1.key"
    _MCSR = f"{_CRP}/monitors/usr1.csr"

    test_key_files = {
        "_PCRT": _PCRT,
        "_PKEY": _PKEY,
        "_PCSR": _PCSR,
        "_MCRT": _MCRT,
        "_MKEY": _MKEY,
        "_MCSR": _MCSR,
    }

    print("[*] Creating temporal test files...")
    subprocess.run(
        f"mkdir -p {_CRP}/producers; mkdir -p {_CRP}/monitors",
        shell=True,
    )
    subprocess.run(
        f"openssl req -newkey rsa:2048 -noenc "
        f'-subj "/C=GL/ST=Semersooq/L=Nuuk/O=test/CN=www.prod-example.com" '
        f"-keyout {_PKEY} -out {_PCSR}",
        shell=True,
    )
    subprocess.run(
        f"openssl x509 -req -sha256 -in {_PCSR} -signkey {_PKEY} -out {_PCRT}",
        shell=True,
    )
    subprocess.run(
        f"openssl req -newkey rsa:2048 -noenc "
        f'-subj "/C=GL/ST=Semersooq/L=Nuuk/O=test/CN=www.mon-example.com" '
        f"-keyout {_MKEY} -out {_MCSR}",
        shell=True,
    )
    subprocess.run(
        f"openssl x509 -req -sha256 -in {_MCSR} -signkey {_MKEY} -out {_MCRT}",
        shell=True,
    )
    subprocess.run(
        "head -n 5 /dev/random | base64 > anasset", shell=True
    )  # Create an auxiliary asset
    yield test_key_files
    print("[*] Removing temporal key files...")
    subprocess.run(
        f"rm -f {' '.join(test_files + list(test_key_files.values()))}",
        shell=True,
    )
    subprocess.run(
        f"rm -rf {_CRP}", shell=True
    )  # Remove only empty dir


@pytest.fixture(scope="session")
def _prod():
    yield Producer("localhost", PCRT, PKEY)


@pytest.fixture(scope="session")
def _mon():
    yield Monitor("localhost", MCRT, MKEY)


# ============= T E S T  ===========================================
@pytest.mark.parametrize(
    "cert, key, result",
    [
        (PCRT, PKEY, True),
        (MCRT, MKEY, True),
        (PCRT, MKEY, False),
        ("", "", False),
    ],
)
def test_key_validation(cert, key, result, setup_keys):
    tmp1 = subprocess.run(
        f"openssl rsa -in {key} -noout -modulus",
        capture_output=True,
        shell=True,
    )
    tmp2 = subprocess.run(
        f"openssl x509 -in {cert} -noout -modulus",
        capture_output=True,
        shell=True,
    )
    tmp1out = tmp1.stdout.decode()
    tmp2out = tmp2.stdout.decode()
    assert (
        tmp1out != "" and tmp2out != "" and tmp1out == tmp2out
    ) == result


class TestProducer:
    @pytest.mark.xfail(raises=requests.exceptions.SSLError)
    # Server should not allow self-signed or unknown CA certificates
    def test_unknown_ca(self, setup_keys):
        unknow_prod = Producer(
            "localhost",
            setup_keys.get("_PCRT"),
            setup_keys.get("_PKEY"),
        )
        unknow_prod.register()

    def test_cli_basic(self):
        ret = subprocess.run("python3 client.py --help", shell=True)
        assert not ret.returncode, "CLI not working as expected"

    def test_init(self, _prod):
        assert (
            _prod.grpkey is not None
        ), "Initialization error. Missing group key"

    def test_sign_before_register(self, _prod):
        # sign before register -> None (error)
        assert (
            _prod.sign(asset="anasset") is None
        ), "Signing should not be allowed before registering"

    def test_register_new(self, _prod):
        # register new key -> member key in base 64
        assert is_base64(
            _prod.register()
        ), "Unexpected error registering the producer in the group"

    def test_register_existent(self, _prod):
        # register an existing key -> None (error)
        # we are just testing the client, not the server, for this type of request
        assert (
            _prod.register() is None
        ), "Clients should not be allowed to register more than once"

    def test_sign_after_register(self, _prod):
        # sign an asset, if OK returns not None and assert is base64
        assert (
            is_base64(_prod.sign(asset="gkey"))
            and Path("sig").is_file()
        ), "Unexpected error signing asset"

    @pytest.mark.parametrize(
        "asset, res", [("gkey", True), ("anasset", False)]
    )
    def test_verify(self, asset, res, _prod):
        # asset and signature match -> True
        # asset and signature do not match -> False
        assert (
            _prod.verify(asset=asset) == res
        ), f"Signature verification failed. (asset: {asset}, expected_result: {res})"


class TestMonitor:

    @pytest.mark.xfail(raises=requests.exceptions.SSLError)
    # Server should not allow self-signed or unknown CA certificates
    def test_unknown_ca(self, setup_keys):
        unknow_mon = Monitor(
            "localhost",
            setup_keys.get("_PCRT"),
            setup_keys.get("_PKEY"),
        )
        unknow_mon.register()

    def test_cli_basic(self):
        ret = subprocess.run(
            "python3 client_mon.py --help", shell=True
        )
        assert not ret.returncode, "CLI not working as expected"

    def test_init(self, _mon):
        assert (
            _mon.memkey is None and _mon.grpkey is not None
        ), "Initialization error. Missing group key"

    def test_sign_before_register(self, _mon):
        # sign before register -> None (error)
        assert (
            _mon.sign(asset="anasset", sig="sig_mon") is None
        ), "Signing should not be allowed before registering"

    def test_revoke_before_register(self, _mon):
        assert (
            _mon.revoke() is None
        ), "Revoking identities should not be allowed before registering"

    def test_register_new(self, _mon):
        # register new key -> member key in base 64
        assert is_base64(
            _mon.register()
        ), "Unexpected error registering the monitor in the group"

    def test_register_existent(self, _mon):
        # register an existing key -> None (error)
        # we are just testing the client, not the server, with this type of request
        assert (
            _mon.register() is None
        ), "Clients should not be allowed to register more than once"

    def test_sign_after_register(self, _mon):
        # sign an asset, if OK returns not None and assert is base64
        assert (
            is_base64(_mon.sign(asset="sig", sig="sig_mon"))
            and Path("sig_mon").is_file()
        ), "Unexpected error signing asset"

    @pytest.mark.parametrize(
        "asset, sig, monitor_mode, res",
        [
            ("gkey", "sig", False, True),
            ("anasset", "sig", False, False),
            ("sig", "sig_mon", True, True),
            ("anasset", "sig_mon", True, False),
        ],
    )
    def test_verify(self, asset, sig, monitor_mode, res, _mon):
        assert (
            _mon.verify(asset=asset, sig=sig, monitor=monitor_mode)
            == res
        ), (
            f"Signature verification failed. (asset: {asset}, sig: {sig}, "
            f"monitor_mode: {monitor_mode}, expected_result: {res})"
        )

    # when does status return None? When sig is not associated to any known identity
    def test_status_unknown_identity(self, _mon):
        assert _mon.status(sig="anasset") is None

    def test_status_before_revoke(self, _mon):
        assert (
            not _mon.status()
        ), "Signature should not be revoked yet"

    def test_revoke(self, _mon):
        assert _mon.revoke(), "Failed to revoke signature"

    def test_status_after_revoke(self, _mon):
        assert _mon.status(), "Signature should be revoked now"

    def test_revoke_twice(self, _mon):
        assert _mon.revoke(), "Signature should be already revoked"

    def test_revoke_unkwnon_identity(self, _mon):
        assert (
            _mon.revoke(sig="anasset") is None
        ), "Revoking unknown identities should not be allowed"


if __name__ == "__main__":
    print(
        f"Basic usage: pytest {Path(__file__).name}. Check Pytest docs for more info"
    )
