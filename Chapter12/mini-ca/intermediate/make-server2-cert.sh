#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl ca \
    -config intermediate.cnf \
    -in  ../server2/server2_csr.pem \
    -out ../server2/server2_cert.pem
