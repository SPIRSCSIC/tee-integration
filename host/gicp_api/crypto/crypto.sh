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
    cd "$org"

    # Generate private key for CA
    openssl genrsa -out ca.key 2048

    # Create a self signed certificate to be used for signing client certificates.
    openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt -subj "/C=$CT/ST=$ST/L=$LC/O=$org/OU=$OU/CN=${org}CA"

    # Generate private keys for the certificates
    openssl genrsa -out user1.key 2048
    openssl genrsa -out user2.key 2048

    # Generate a Certificate Signing Request (CSR) for each private key
    openssl req -new -key user1.key -out user1.csr -subj "/C=$CT/ST=$ST/L=$LC/O=$org/OU=$OU/CN=${org}User1"
    openssl req -new -key user2.key -out user2.csr -subj "/C=$CT/ST=$ST/L=$LC/O=$org/OU=$OU/CN=${org}User2"

    # Use the CA to sign the certificates
    openssl x509 -req -in user1.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out user1.crt -days 500 -sha256
    openssl x509 -req -in user2.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out user2.crt -days 500 -sha256
    cd ..
    cat $org/ca.crt >> chain.pem
done
