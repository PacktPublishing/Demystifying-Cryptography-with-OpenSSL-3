#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl req \
    -config server.cnf \
    -new \
    -key private/server_keypair.pem \
    -out server_csr.pem \
    -text
