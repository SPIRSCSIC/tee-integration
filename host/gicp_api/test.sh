#!/usr/bin/env bash

CRP=../crypto
PCRT=$CRP/producers/usr1.crt
PKEY=$CRP/producers/usr1.key
MCRT=$CRP/monitors/usr1.crt
MKEY=$CRP/monitors/usr1.key

echo "Running client commands..."
echo -e "\nRegistering client"
python3 gicp_api/client.py -r -C $PCRT -K $PKEY -H localhost
echo -e "\nSigning asset"
python3 gicp_api/client.py -s -a gkey -S sig -C $PCRT -K $PKEY -H localhost
echo -e "\nVerifying asset signature"
python3 gicp_api/client.py -v -a gkey -S sig -C $PCRT -K $PKEY -H localhost

echo -e "\nRunning monitor commands..."
echo -e "\nRegistering monitor"
python3 gicp_api/client_mon.py -r -C $MCRT -K $MKEY -H localhost
echo -e "\nVerifying asset signature"
python3 gicp_api/client_mon.py -v -a gkey -S sig -C $MCRT -K $MKEY -H localhost
echo -e "\nSigning asset signature"
python3 gicp_api/client_mon.py -s -a sig -S sig_mon -C $MCRT -K $MKEY -H localhost
echo -e "\nVerifying (monitor) signature of asset signature"
python3 gicp_api/client_mon.py -vm -a sig -S sig_mon -C $MCRT -K $MKEY -H localhost
echo -e "\nRevoking identity linked to asset signature"
python3 gicp_api/client_mon.py -R -S sig -C $MCRT -K $MKEY -H localhost
echo -e "\nChecking status of identity linked to asset signature"
python3 gicp_api/client_mon.py -t -S sig -C $MCRT -K $MKEY -H localhost
