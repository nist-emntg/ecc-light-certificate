#!/bin/sh

#
# Generate certificates for the Contiki UDP client
# Tony Cheneau <tony.cheneau@nist.gov>
#

TOOL_PATH=../tools

# generate certificate
$TOOL_PATH/gen-cert cacert
$TOOL_PATH/gen-cert cert cacert
$TOOL_PATH/gen-cert client2 cacert

# print the corresponding C code
$TOOL_PATH/convert-cert-to-array -p cacert raw_cacert
$TOOL_PATH/convert-cert-to-array cert raw_cert
$TOOL_PATH/convert-cert-to-array -p client2 raw_client2

# you might want to comment the following line
rm -f cacert cert client2
