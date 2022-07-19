#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl ca \
    -config intermediate.cnf \
    -policy policy_client_cert \
    -extensions v3_client_cert \
    -in  ../client/client_csr.pem \
    -out ../client/client_cert.pem
