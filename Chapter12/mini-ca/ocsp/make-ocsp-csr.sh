#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl req \
    -config ocsp.cnf \
    -new \
    -key private/ocsp_keypair.pem \
    -out ocsp_csr.pem \
    -text
