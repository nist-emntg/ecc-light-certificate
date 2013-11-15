#!/bin/sh

#
# Generate certificates for the example client/server
# Tony Cheneau <tony.cheneau@nist.gov>
#

TOOL_PATH=../tools

# generate certificate
$TOOL_PATH/gen-cert cacert
sleep 1
$TOOL_PATH/gen-cert cacert2
sleep 1
$TOOL_PATH/gen-cert client1 cacert
sleep 1
$TOOL_PATH/gen-cert server cacert
sleep 1
$TOOL_PATH/gen-cert client2 cacert2

# print the corresponding C code
echo "common"
$TOOL_PATH/convert-cert-to-array -p cacert raw_cacert
echo "server"
$TOOL_PATH/convert-cert-to-array server raw_cert
echo "client"
$TOOL_PATH/convert-cert-to-array client1 raw_cert
echo "bad client"
$TOOL_PATH/convert-cert-to-array client2 raw_bad_cert

# you might want to comment the following line
rm -f cacert{,2} client{1,2} server
