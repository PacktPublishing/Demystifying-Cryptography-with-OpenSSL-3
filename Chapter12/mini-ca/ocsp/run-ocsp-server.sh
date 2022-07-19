#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl ocsp \
    -port 4480 \
    -index ../intermediate/index.txt \
    -CA ../intermediate/intermediate_cert.pem \
    -rkey private/ocsp_keypair.pem \
    -rsigner ocsp_cert.pem
