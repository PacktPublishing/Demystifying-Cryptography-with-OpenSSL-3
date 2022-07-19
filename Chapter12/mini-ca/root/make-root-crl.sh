#!/bin/sh

set -e

export LD_LIBRARY_PATH=/opt/openssl-3.0.0/lib64
export PATH="/opt/openssl-3.0.0/bin:$PATH"

openssl ca -config root.cnf -gencrl -out root_crl.pem
openssl crl -in root_crl.pem -out root_crl.der -outform DER
openssl crl -in root_crl.der -inform DER -out root_crl.pem -text
