#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

$ openssl genpkey \
    -algorithm ED448 \
    -out leaf_keypair.pem

$ openssl req \
    -new \
    -subj "/CN=Leaf" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -key leaf_keypair.pem \
    -out leaf_csr.pem

$ openssl x509 \
    -req \
    -in leaf_csr.pem \
    -copy_extensions copyall \
    -CA intermediate_cert.pem \
    -CAkey intermediate_keypair.pem \
    -days 3650 \
    -out leaf_cert.pem
