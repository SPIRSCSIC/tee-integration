#!/usr/bin/env bash

if [ $# -lt 1 ]; then
    echo "Usage: ./crypto.sh <org1> [<org2> [<orgN>]]"
    exit 1
fi

# Define details for the certificates
CT="ES"
ST="Comunidad de Madrid"
LC="Madrid"
OU="PoC"

for org in "$@"; do
    mkdir -p "$org"
    # Generate private key for CA
    openssl genrsa -out $org/ca.key 2048
    # Create a self signed certificate to be used for signing client certificates.
    openssl req -x509 -new -nodes -key $org/ca.key -sha256 -days 1024 -out $org/ca.crt -subj "/C=$CT/ST=$ST/L=$LC/O=$org/OU=$OU/CN=${org}CA"
    # Generate private keys for the certificates
    openssl genrsa -out $org/usr1.key 2048
    openssl genrsa -out $org/usr2.key 2048
    # Generate a Certificate Signing Request (CSR) for each private key
    openssl req -new -key $org/usr1.key -out $org/usr1.csr -subj "/C=$CT/ST=$ST/L=$LC/O=$org/OU=$OU/CN=${org}User1"
    openssl req -new -key $org/usr2.key -out $org/usr2.csr -subj "/C=$CT/ST=$ST/L=$LC/O=$org/OU=$OU/CN=${org}User2"
    # Use the CA to sign the certificates
    openssl x509 -req -in $org/usr1.csr -CA $org/ca.crt -CAkey $org/ca.key -CAcreateserial -out $org/usr1.crt -days 500 -sha256
    openssl x509 -req -in $org/usr2.csr -CA $org/ca.crt -CAkey $org/ca.key -CAcreateserial -out $org/usr2.crt -days 500 -sha256
done
eval "cat {$(IFS=','; echo "$*")}/ca.crt" > chain.pem
