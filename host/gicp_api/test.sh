#!/usr/bin/env bash

echo "Running client commands..."
echo -e "\nRegistering client"
python3 gicp_api/client.py -r
echo -e "\nSigning asset"
python3 gicp_api/client.py -s -a gkey -S sig
echo -e "\nVerifying asset signature"
python3 gicp_api/client.py -v -a gkey -S sig

echo -e "\nRunning revoker commands..."
echo -e "\nRegistering revoker"
python3 gicp_api/client_rev.py -r
echo -e "\nVerifying asset signature"
python3 gicp_api/client_rev.py -v -a gkey -S sig
echo -e "\nSigning asset signature"
python3 gicp_api/client_rev.py -s -a sig -S sig_rev
echo -e "\nVerifying (revoker) signature of asset signature"
python3 gicp_api/client_rev.py -vr -a sig -S sig_rev
echo -e "\nRevoking identity linked to asset signature"
python3 gicp_api/client_rev.py -R -S sig
echo -e "\nChecking status of identity linked to asset signature"
python3 gicp_api/client_rev.py -t -S sig
