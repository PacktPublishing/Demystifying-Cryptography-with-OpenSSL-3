#!/bin/sh

set -e

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

cat \
    ../intermediate/intermediate_cert.pem \
    ../root/root_cert.pem \
    >certfile.pem

openssl pkcs12 \
    -export \
    -inkey private/client_keypair.pem \
    -in client_cert.pem \
    -certfile certfile.pem \
    -passout 'pass:SuperPa$$w0rd' \
    -out client_cert.p12 
