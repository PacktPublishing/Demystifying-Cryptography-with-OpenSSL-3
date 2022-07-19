#!/bin/sh

set -e

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl crl \
    -in intermediate_crl.pem \
    -noout \
    -text
