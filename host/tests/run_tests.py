import argparse
import subprocess
from datetime import datetime
from pathlib import Path
from time import sleep


CONT_NAME = "spirs_test"
SDK_NAME = "spirs_tee_sdk_test"
OUTPUT = subprocess.DEVNULL
CWD = Path(__file__)
REPORT_NAME = ".report.json"
REPORT_FILE = CWD.parent / f"results/{REPORT_NAME}"
TIME_LOG = CWD.parent / "results/performance.log"
SERVER_LOG = CWD.parent / "results/server.log"


def strfy_time(seconds):
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return (
        (f"{h:d}h " if h > 0 else "")
        + (f"{m:02d}m " if m > 0 else "")
        + f"{s:02d}s"
    )


def _ssh_qemu_cmd(cmd):
    subprocess.run(
        f"docker exec -t {CONT_NAME} ssh"
        f" -i /keystone/build/overlay/root/.ssh/id_rsa "
        f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-p 7777 root@localhost {cmd}",
        shell=True,
        stdout=OUTPUT,
        stderr=OUTPUT,
    )


def setup_server(alg):
    # copy crypto material
    subprocess.run(
        f"docker exec -t {CONT_NAME} scp"
        f" -i /keystone/build/overlay/root/.ssh/id_rsa "
        f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-P 7777 -r crypto root@localhost:/root",
        shell=True,
        stdout=OUTPUT,
        stderr=OUTPUT,
    )
    # the server is started using <algorithm>
    print(f"[*] Creating signature group for monitors ({alg})")
    _ssh_qemu_cmd(f"./gdemos.ke groupsig -s {alg} -a _mon --quiet")
    print(f"[*] Creating signature group for producers ({alg})")
    _ssh_qemu_cmd(f"./gdemos.ke groupsig -s {alg} --quiet")
    print("[*] Running the server in background...")
    _ssh_qemu_cmd(
        f"python3 ./gicp_api/server.py -C crypto/gms/usr1.crt "
        f"-K crypto/gms/usr1.key -c crypto/chain.pem > {SERVER_LOG} &"
    )
    sleep(15)  # Wait for server to bootstrap


def setup_container():
    root = CWD.parents[2]
    print("[*] Setting up container [scripts/container.sh] ETA 5~10m")
    subprocess.run(
        f"bash scripts/container.sh -n {CONT_NAME} -r {SDK_NAME} -p 5001 --test",
        cwd=root,
        shell=True,
        stdout=OUTPUT,
        stderr=OUTPUT,
    )
    print("[+] Container ready")
    print(f"[*] Removing previous execution artifacts")
    subprocess.run(
        f"""docker exec {CONT_NAME} bash -c 'ps -eo pid,comm """
        """| awk "{if(\\$2 == \\"qemu-system-ris\\") print \\$1}" """
        """| xargs -r kill -9'""",
        shell=True,
    )
    print("[*] Compiling qemu image in the container...")
    # WITHIN DOCKER
    ret = subprocess.run(
        f"docker exec -id {CONT_NAME} make -C build -j qemu",
        shell=True,
        stdout=OUTPUT,
        stderr=OUTPUT,
    )
    sleep(10)  # Wait for qemu image to be compiled
    # TODO: try/catch if cmd execution error
    if ret.returncode != 0:
        print(f"[-] Unexpected error compiling qemu image")
        raise RuntimeError("Server could not be started")
    else:
        print("[+] Qemu image compiled successfully")
    # TODO: Test different algorithms ?
    setup_server("cpy06")


def run_test_with_coverage(verbose):
    print("[*] Running coverage tests")
    subprocess.run(
        f"docker exec -t -w /spirs_tee_sdk/host/gicp_api "
        f"{CONT_NAME} pytest --cov --cov-config=.coveragerc "
        f"--cov-report json:{REPORT_NAME} "
        f"{'-v' if verbose > 0 else ''} test_static.py",
        shell=True,
    )


def run_tests_no_coverage(verbose):
    print("[*] Running test without coverage")
    subprocess.run(
        f"docker exec -t -w /spirs_tee_sdk/host/gicp_api "
        f"{CONT_NAME} pytest --json-report --json-report-file={REPORT_NAME} "
        f"{'-v' if verbose > 0 else ''} test_static.py",
        shell=True,
    )


def retrieve_test_results():
    print("[*] Retrieving test results")
    subprocess.run(
        f"docker cp {CONT_NAME}:/spirs_tee_sdk/host/gicp_api/{REPORT_NAME} "
        f"{REPORT_FILE}",
        shell=True,
    )


def teardown_container():
    print("[*] Stopping container...")
    ret = subprocess.run(f"docker stop {CONT_NAME}", shell=True)
    if ret.returncode == 0:
        print("[+] Container stopped successfully")
    elif ret.returncode == 256:
        print("[*] The container does not appear to be running")
    else:
        print(
            f"[-] Unexpected error stopping the container "
            f"(errno: {ret.returncode})"
        )


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Test GiCP API, classes and methods"
    )
    parser.add_argument(
        "-c",
        "--cov",
        "--coverage",
        action="store_true",
        default=False,
        help="Includes coverage information in the report",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Verbose output (repeat for increased verbosity)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    _start = datetime.now()
    try:
        _args = _parse_args()
        if _args.verbose > 1:
            OUTPUT = None
        setup_container()
        _test_start = datetime.now()
        if _args.cov:
            run_test_with_coverage(_args.verbose)
        else:
            run_tests_no_coverage(_args.verbose)
        subprocess.run(
            f"echo '9;Run tests;"
            f"{strfy_time((datetime.now() - _test_start).seconds)}' "
            f">> {TIME_LOG}",
            shell=True,
        )
        retrieve_test_results()
        teardown_container()
        print(
            f"[*] Server log should be now available in host/tests directory"
        )
        print("[+] Test execution completed successfully")
        subprocess.run(
            f"python3 {CWD.parent / 'report_formatter.py'} -m",
            shell=True,
        )
    except Exception as e:
        print(f"[!] FATAL ERROR {e}")
        print("[!] Execution failed")
        teardown_container()
    finally:
        print(
            f"[*] Time elapsed: {strfy_time((datetime.now() - _start).seconds)}"
        )
        # TODO: add test time
        subprocess.run(
            f"echo '--------------------\n"
            f"TOTAL TIME {strfy_time((datetime.now() - _start).seconds)}' "
            f">> {TIME_LOG}",
            shell=True,
        )
        print("[*] Exiting...")
