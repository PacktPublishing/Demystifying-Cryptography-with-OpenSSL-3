#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl req \
    -config client.cnf \
    -new \
    -key private/client_keypair.pem \
    -out client_csr.pem \
    -text
