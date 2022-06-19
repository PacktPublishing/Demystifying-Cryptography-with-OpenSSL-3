#!/bin/sh

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64

./tls-server2 \
    4433 \
    server_keypair.pem \
    server_cert.pem \
    ca_cert.pem
