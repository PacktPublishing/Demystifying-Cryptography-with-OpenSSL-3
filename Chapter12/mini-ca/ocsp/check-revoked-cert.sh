#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl ocsp \
    -url http://localhost:4480 \
    -sha256 \
    -CAfile ../root/root_cert.pem \
    -issuer ../intermediate/intermediate_cert.pem \
    -cert ../server2/server2_cert.pem
