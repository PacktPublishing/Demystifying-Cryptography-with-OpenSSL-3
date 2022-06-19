#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl pkcs12 \
    -export \
    -inkey client_keypair.pem \
    -in client_cert.pem \
    -certfile ca_cert.pem \
    -passout 'pass:SuperPa$$w0rd' \
    -out client_cert.p12
