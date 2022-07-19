#!/bin/sh

set -e

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

# Issue a CRL.
openssl ca \
    -config intermediate.cnf \
    -gencrl \
    -out intermediate_crl.pem

# Convert to DER.
openssl crl \
    -in intermediate_crl.pem \
    -out intermediate_crl.der \
    -outform DER

# Add the text representation to PEM.
openssl crl \
    -in intermediate_crl.der \
    -inform DER \
    -out intermediate_crl.pem \
    -text
