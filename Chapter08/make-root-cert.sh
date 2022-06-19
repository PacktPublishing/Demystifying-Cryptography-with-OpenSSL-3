#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl genpkey \
    -algorithm ED448 \
    -out root_keypair.pem

openssl req \
    -new \
    -subj "/CN=Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -key root_keypair.pem \
    -out root_csr.pem

openssl x509 \
    -req \
    -in root_csr.pem \
    -copy_extensions copyall \
    -key root_keypair.pem \
    -days 3650 \
    -out root_cert.pem
