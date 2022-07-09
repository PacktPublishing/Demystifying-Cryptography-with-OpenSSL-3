#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64

./tls-client-non-blocking \
    localhost \
    4433 \
    ca_cert.pem
