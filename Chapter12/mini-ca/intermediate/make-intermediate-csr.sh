#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl req \
    -config intermediate.cnf \
    -new \
    -key private/intermediate_keypair.pem \
    -out intermediate_csr.pem \
    -text
