#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl ca \
    -config intermediate.cnf \
    -extensions v3_ocsp_cert \
    -in  ../ocsp/ocsp_csr.pem \
    -out ../ocsp/ocsp_cert.pem
