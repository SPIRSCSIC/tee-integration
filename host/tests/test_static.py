# https://gitlab.gicp.es/spirs/libgroupsig/-/tree/master/src/wrappers/python?ref_type=heads
import subprocess
import os
import pytest
import base64
import urllib3

from client import Producer
from client_mon import Monitor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============= A U X =============================================

def is_base64(s):
    try:
        print(f"original: {s}")
        # Attempt base64 decoding, encode again and compare against original input
        return base64.b64encode(base64.b64decode(str(s))) == s.encode()
    except Exception:
        return False


# ============= F I X T U R E S ===================================

# origin: /spirs_tee_sdk/crypto
# dest: /spirs_tee_sdk/host/gicp_api/test_static.py
CRP = os.path.join(__file__.split('/host/gicp_api')[0], 'crypto')
PCRT = f"{CRP}/producers/usr1.crt"
PKEY = f"{CRP}/producers/usr1.key"
PCSR = f"{CRP}/producers/usr1.csr"
MCRT = f"{CRP}/monitors/usr1.crt"
MKEY = f"{CRP}/monitors/usr1.key"
MCSR = f"{CRP}/monitors/usr1.csr"

# test_files = [PCRT, PKEY, PCSR, MCRT, MKEY, MCSR,
test_files = ['gkey', 'gkey_mon', 'mkey', 'mkey_mon', 'sig', 'sig_mon ', 'anasset']


# TODO: test with self-signed cert, so server should return sslError unknown CA
# Until then, this fixture is useless
# @pytest.fixture(scope='session')
def setup_keys():
    print("[*] Creating temporal test files...")
    os.system(f'mkdir -p {CRP}/producers; mkdir -p {CRP}/monitors')
    os.system(f'openssl req -newkey rsa:2048 -noenc '
              f'-subj "/C=GL/ST=Semersooq/L=Nuuk/O=test/CN=www.prod-example.com" '
              f'-keyout {PKEY} -out {PCSR}'
              )
    os.system(f'openssl x509 -req -sha256 -in {PCSR} -signkey {PKEY} -out {PCRT}')
    os.system(f'openssl req -newkey rsa:2048 -noenc '
              f'-subj "/C=GL/ST=Semersooq/L=Nuuk/O=test/CN=www.mon-example.com" '
              f'-keyout {MKEY} -out {MCSR}'
              )
    os.system(f'openssl x509 -req -sha256 -in {MCSR} -signkey {MKEY} -out {MCRT}')
    os.system('head -n 5 /dev/random | base64 > anasset')  # Create an auxiliary asset
    # assert os.path.isfile(MCRT) and os.path.isfile(MKEY) and os.path.isfile(PCRT) and os.path.isfile(PKEY)
    yield
    # TODO: remove all key files generated during test execution
    print("[*] Removing temporal test files...")
    # os.system(f'rm -fr ./{CRP} 2> /dev/null') NOT SECURE VULNERABLE TO INJECTION
    os.system(f"rm {' '.join(test_files)} 2> /dev/null")
    os.system(f'rmdir {CRP}')  # Remove only empty dir


@pytest.fixture(scope='session')
def setup_test_files():
    print("[*] Creating temporal test files...")
    os.system('head -n 5 /dev/random | base64 > anasset')  # Create an auxiliary asset
    # os.system('head -n 5 /dev/random | base64 > sig')  # Create an aux (fake) signature
    yield
    # TODO: remove all key files generated during test execution
    print("[*] Removing temporal test files...")
    os.system(f"rm {' '.join(test_files)} 2> /dev/null")


@pytest.fixture(scope='session')
def _prod():
    yield Producer('localhost', PCRT, PKEY)


@pytest.fixture(scope='session')
def _mon():
    yield Monitor('localhost', MCRT, MKEY)


# ============= T E S T  ===========================================
@pytest.mark.parametrize("cert, key, result", [
    (PCRT, PKEY, True), (MCRT, MKEY, True), (PCRT, MKEY, False), ('', '', False)])
def test_key_validation(cert, key, result, setup_test_files):
    tmp1 = subprocess.run(f'openssl rsa -in {key} -noout -modulus'.split(' '), stdout=subprocess.PIPE)
    tmp2 = subprocess.run(f'openssl x509 -in {cert} -noout -modulus'.split(' '), stdout=subprocess.PIPE)
    assert (tmp1.stdout.decode('utf-8') != '' and
            tmp1.stdout.decode('utf-8') == tmp2.stdout.decode('utf-8')) == result
    
    'openssl pkey -in privateKey.key -pubout -outform pem | sha256sum'
    'openssl x509 -in certificate.crt -pubkey -noout -outform pem | sha256sum'
    'openssl req -in CSR.csr -pubkey -noout -outform pem | sha256sum '


class TestProducer:
    def test_init(self, _prod):
        assert _prod.grpkey is not None, "Initialization error. Missing group key"
    
    def test_sign_before_register(self, _prod):
        # sign before register -> None (error)
        assert _prod.sign(asset='anasset') is None, \
            "Signing should not be allowed before registering"
    
    def test_register_new(self, _prod):
        # register new key -> member key in base 64
        assert is_base64(_prod.register()), \
            "Unexpected error registering the producer in the group"
    
    def test_register_existent(self, _prod):
        # register an existing key -> None (error)
        # we are not testing the server upon receiving this type of request,
        # we are just testing the client
        assert _prod.register() is None, \
            "Clients should not be allowed to register more than once"
    
    def test_sign_after_register(self, _prod):
        # sign an asset, if OK returns not None and assert is base64
        assert is_base64(_prod.sign(asset='gkey')) and os.path.isfile('sig'), \
            "Unexpected error signing asset"
    
    @pytest.mark.parametrize("asset, res", [('gkey', True), ('anasset', False)])
    def test_verify(self, asset, res, _prod):
        # asset and signature match -> True
        # asset and signature do not match -> False
        assert _prod.verify(asset=asset) is res, \
            f"Signature verification failed. (asset: {asset}, expected_result: {res})"


class TestMonitor:
    def test_init(self, _mon):
        assert _mon.memkey is None and _mon.grpkey is not None, \
            "Initialization error. Missing group key"
    
    def test_sign_before_register(self, _mon):
        # sign before register -> None (error)
        assert _mon.sign(asset='anasset', sig='sig_mon') is None, \
            "Signing should not be allowed before registering"
    
    def test_revoke_before_register(self, _mon):
        assert _mon.revoke() is None, \
            "Revoking identities should not be allowed before registering"
    
    # when does status return None?
    # def test_status_before_register(self, _mon):
    #    assert _mon.revoke() is None
    
    def test_register_new(self, _mon):
        # register new key -> member key in base 64
        assert is_base64(_mon.register()), \
            "Unexpected error registering the monitor in the group"
    
    def test_register_existent(self, _mon):
        # register an existing key -> None (error)
        # we are not testing the server upon receiving this type of request,
        # we are just testing the client
        assert _mon.register() is None, \
            "Clients should not be allowed to register more than once"
    
    def test_sign_after_register(self, _mon):
        # sign an asset, if OK returns not None and assert is base64
        assert is_base64(_mon.sign(asset='sig', sig='sig_mon')) and os.path.isfile('sig_mon'), \
            "Unexpected error signing asset"
    
    """unrolled test cases for mon.verify()
    @pytest.mark.parametrize("asset, res", [('gkey', True), ('anasset', False)])
    def test_verify(self, asset, res, _mon):
        assert _mon.verify(asset=asset) is res
    
    @pytest.mark.parametrize("asset, res", [('gkey', True), ('anasset', False)])
    def test_verify_monitor(self, asset, res, _mon):
        assert _mon.verify(asset=asset, monitor=True) is res
    """
    
    # Compressed test cases for mon.verify()
    @pytest.mark.parametrize("asset, sig, monitor_mode, res", [
        ('gkey', 'sig', False, True), ('anasset', 'sig', False, False),
        ('sig', 'sig_mon', True, True), ('anasset', 'sig_mon', True, False)])
    def test_verify(self, asset, sig, monitor_mode, res, _mon):
        assert _mon.verify(asset=asset, sig=sig, monitor=monitor_mode) is res, (
            f"Signature verification failed. (asset: {asset}, sig: {sig}, "
            f"monitor_mode: {monitor_mode}, expected_result: {res})")
    
    """
    status(sig) -> True (ok)
    revoke(sig) -> True (ok)
    status(sig) -> False (revoked)
    revoke(sig) -> error or False? (already revoked)
    """
    
    def test_status_before_revoke(self, _mon):
        assert _mon.status() is False, \
            "Signature should not be revoked yet"
    
    def test_revoke(self, _mon):
        assert _mon.revoke(), \
            "Failed to revoke signature"
    
    def test_status_after_revoke(self, _mon):
        assert _mon.status(), \
            "Signature should be revoked now"
    
    def test_revoke_twice(self, _mon):
        assert _mon.revoke() is False, \
            "Signature should be already revoked"


if __name__ == '__main__':
    print(f"Basic usage: pytest {os.path.split(__file__)[1]}. Check Pytest docs for more info")
