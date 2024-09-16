#!/usr/bin/env sh

openssl ecparam -name prime256v1 -genkey -noout -out /etc/heimdall/keys/signer.pem
chown -R 10001:10001 /etc/heimdall/keys