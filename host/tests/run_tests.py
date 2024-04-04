import os
from time import sleep
from datetime import datetime

report_name = '.report.json'
report_file = os.path.join(os.path.split(__file__)[0], 'results', report_name)
time_log = os.path.join(os.path.split(__file__)[0], 'results', 'performance.log')
server_log = os.path.join(os.path.split(__file__)[0], 'results', 'server.log')


def strfy_time(seconds):
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return (f"{h:d}h " if h > 0 else '') + (f"{m:02d}m " if m > 0 else '') + f"{s:02d}s"


def _ssh_qemu_cmd(cmd):
    os.system(f"docker exec -t spirs ssh"
              f" -i /keystone/build/overlay/root/.ssh/id_rsa "
              f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
              f"-p 7777 root@localhost {cmd}"
              )


def setup_server(alg):
    # TODO: integrate commands into script (eg. bash setup_server.sh <alg>) the server is started using <algorithm>
    _allowed = ['cpy06']
    if alg not in _allowed: raise ValueError(f"Unknow algorithm '{alg}'. Allowed: {_allowed}")
    print(f"[*] Creating signature group for producers ({alg})")
    _ssh_qemu_cmd(f'./gdemos.ke groupsig -s {alg}')
    print(f"[*] Creating signature group for monitors ({alg})")
    _ssh_qemu_cmd(f'./gdemos.ke groupsig -s {alg} -a _mon')
    print("[*] Running the server in background...")
    _ssh_qemu_cmd('python3 ./gicp_api/server.py '
                  '-C crypto/gms/usr1.crt '
                  '-K crypto/gms/usr1.key '
                  f'-c crypto/chain.pem > {server_log} &')
    sleep(7)  # Wait for server to bootstrap


def setup_container():
    # 'docker run --name spirs -it --rm -d -v $PWD/spirs_tee_sdk:/spirs_tee_sdk spirs_keystone:22.04'
    os.chdir(__file__.split('/host/tests')[0])  # go to project root dir
    print("[*] Setting up environment [scripts/setup.sh]")
    os.system(f"bash scripts/setup.sh")
    print("[*] Setting up container [scripts/container.sh] ETA 5~10m")
    os.system(f"bash scripts/container.sh")
    print('[+] Container ready')
    print("[*] Compiling qemu image in the container...")
    # WITHIN DOCKER
    # /usr/bin/time -f "%E elapsed [h:m:s]" sleep 2
    ret = os.system('docker exec -id -w /spirs_tee_sdk spirs make -C build -j qemu')
    sleep(5)  # Wait for qemu image to be compiled
    # TODO: try/catch if cmd execution error
    if ret != 0:
        print(f"[-] Unexpected error compiling qemu image")
        raise RuntimeError("Server could not be started")
    else:
        print('[+] Qemu image compiled successfully')
    # TODO: Test different algorithms ?
    setup_server('cpy06')
    """
    print("[DEBUG] NOW START THE SERVER MANUALLY")
    while True:
        if input("[DEBUG] Write 'continue' once the server is started.\n").lower() == 'continue':
            break
        else:
            print('[DEBUG] Command unknown')
    
    # TODO: automate server initialization
    """


def run_test_with_coverage():
    print('[*] Running coverage tests')
    os.system("docker exec -t -w /spirs_tee_sdk/host/gicp_api "
              f"spirs pytest --cov=. --cov-report json:{report_name} test_static.py")


def run_tests_no_coverage():
    print('[*] Running test without coverage')
    os.system("docker exec -t -w /spirs_tee_sdk/host/gicp_api "
              f"spirs pytest --json-report --json-report-file={report_name} -v test_static.py")


def retrieve_test_results():
    print("[*] Retrieving test results")
    ret = os.system(f"docker cp "
                    f"spirs:/spirs_tee_sdk/host/gicp_api/{report_name} "
                    f"{report_file}")
    """
    if ret != 0:
        print(f'[-] Unexpected error retrieving the report. (errno: {ret})')
    else:
        print(f'[+] Report retrieved successfully ({report_name})')
    
    # TODO: secure copy to get that file from qemu
    os.system('docker exec -t -w /spirs_tee_sdk/host/gicp_api spirs '
              'scp -i /keystone/build/overlay/root/.ssh/id_rsa '
              '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
              '-P 7777 root@localhost:server.log .')
    ret = os.system(f"docker cp "
                    f"spirs:/spirs_tee_sdk/host/gicp_api/server.log "
                    f"{os.path.join(os.path.split(__file__)[0], 'server.log')}")
    if ret != 0:
        print(f'[-] Unexpected error retrieving server log. (errno: {ret})')
    else:
        print('[+] Server log retrieved successfully (server.log)')
    """


def teardown_container():
    print('[*] Stopping container...')
    ret = os.system(f"docker stop spirs")
    if ret == 0:
        print('[+] Container stopped successfully')
    elif ret == 256:
        print('[*] The container does not appear to be running')
    else:
        print(f'[-] Unexpected error stopping the container (errno: {ret})')


def _parse_args(cmd=None):
    import argparse
    parser = argparse.ArgumentParser(
        prog=os.path.split(__file__)[1],
        description="Test GiCP API, classes and methods"
    )
    parser.add_argument(
        '-c', '--cov', '--coverage',
        action='store_true',
        default=False,
        help='Includes coverage information in the report'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        default=False,
        help='Reduces the verbosity of the executed commands'
    )
    return parser.parse_args(cmd)


if __name__ == '__main__':
    _start = datetime.now()
    try:
        _args = _parse_args()
        setup_container()
        _test_start = datetime.now()
        if _args.cov:
            run_test_with_coverage()
        else:
            run_tests_no_coverage()
        os.system(f"echo '9;Run tests; {strfy_time((datetime.now() - _test_start).seconds)}' >> {time_log}")
        retrieve_test_results()
        teardown_container()
        print(f'[*] Server log should be now available in host/tests directory')
        print('[+] Execution completed successfully.')
    except Exception as e:
        print(f'[!] FATAL ERROR {e}')
        print('[!] Execution failed')
        teardown_container()
    finally:
        print(f"[*] Time elapsed: {strfy_time((datetime.now() - _start).seconds)}")
        # TODO: add test time
        os.system(f"echo '--------------------\n"
                  f"TOTAL TIME {strfy_time((datetime.now() - _start).seconds)}' >> {time_log}"
                  )
        print('[*] Exiting...')
