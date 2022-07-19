#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

mkdir -p private
chmod 0700 private

openssl genpkey \
    -algorithm ED448 \
    -out private/root_keypair.pem
