#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl ca \
    -config root.cnf \
    -extensions v3_root_cert \
    -selfsign \
    -in root_csr.pem \
    -out root_cert.pem
