#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl req \
    -config root.cnf \
    -new \
    -key private/root_keypair.pem \
    -out root_csr.pem \
    -text
