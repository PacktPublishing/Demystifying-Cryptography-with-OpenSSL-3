#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl pkcs12 \
    -in client_cert.p12 \
    -passin 'pass:SuperPa$$w0rd' \
    -noenc \
    -info
