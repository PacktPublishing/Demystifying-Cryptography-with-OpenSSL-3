#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64

./tls-cert-pinning \
    localhost \
    4433 \
    server_cert.pem
