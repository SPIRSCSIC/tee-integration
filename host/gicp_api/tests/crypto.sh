#!/usr/bin/env bash

if [ $# -lt 1 ]; then
    echo "Usage: ./crypto.sh <org1> [<org2> [<orgN>]]"
    exit 1
fi

# Define details for the certificates
COUNTRY="ES"
STATE="Comunidad de Madrid"
LOCALITY="Madrid"
ORGANIZATION_UNIT="PoC"
EMAIL="poc@gicp.es"

for org in "$@"; do
    mkdir -p "$org"
    cd "$org"

    # Generate private key for CA
    openssl genrsa -out ca.key 2048

    # Create a self signed certificate to be used for signing client certificates.
    openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$org/OU=$ORGANIZATION_UNIT/CN=$EMAIL"

    # Generate private key for the certificate
    openssl genrsa -out cert1.key 2048
    openssl genrsa -out cert2.key 2048

    # Generate a Certificate Signing Request (CSR) for the private key
    openssl req -new -key cert1.key -out cert1.csr -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$org/OU=$ORGANIZATION_UNIT/CN=$EMAIL"
    openssl req -new -key cert2.key -out cert2.csr -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$org/OU=$ORGANIZATION_UNIT/CN=$EMAIL"

    # Use the CA to sign the certificate
    openssl x509 -req -in cert1.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out cert1.crt -days 500 -sha256
    openssl x509 -req -in cert2.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out cert2.crt -days 500 -sha256
    cd ..
    cat $org/ca.crt >> chain.pem
done
