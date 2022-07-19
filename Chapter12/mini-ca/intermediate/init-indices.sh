#!/bin/sh

set -e
set -x

mkdir -p issued
echo -n >index.txt
echo 01 >crlnumber.txt
