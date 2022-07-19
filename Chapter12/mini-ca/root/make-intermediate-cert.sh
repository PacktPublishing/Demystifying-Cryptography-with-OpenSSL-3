#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl ca \
    -config root.cnf \
    -extensions v3_intermediate_cert \
    -in  ../intermediate/intermediate_csr.pem \
    -out ../intermediate/intermediate_cert.pem
