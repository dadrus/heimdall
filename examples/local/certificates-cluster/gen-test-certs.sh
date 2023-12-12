#!/bin/bash

# Generate some test certificates which are used by the regression test suite:
#
#   tests/tls/ca.{crt,key}          Self signed CA certificate.
#   tests/tls/redis.{crt,key}       A certificate with no key usage/policy restrictions.
#   tests/tls/client.{crt,key}      A certificate restricted for SSL client usage.
#   tests/tls/server.{crt,key}      A certificate restricted for SSL server usage.
#   tests/tls/redis.dh              DH Params file.

generate_cert() {
    local name=$1
    local cn="$2"
    local opts="$3"

    local keyfile=tests/tls/${name}.key
    local certfile=tests/tls/${name}.crt

    [ -f $keyfile ] || openssl genrsa -out $keyfile 2048
    openssl req \
        -new -sha256 \
        -subj "/O=Redis Test/CN=$cn" \
        -key $keyfile | \
        openssl x509 \
            -req -sha256 \
            -CA tests/tls/ca.crt \
            -CAkey tests/tls/ca.key \
            -CAserial tests/tls/ca.txt \
            -CAcreateserial \
            -days 365 \
            $opts \
            -out $certfile
}

mkdir -p tests/tls
[ -f tests/tls/ca.key ] || openssl genrsa -out tests/tls/ca.key 4096
openssl req \
    -x509 -new -nodes -sha256 \
    -key tests/tls/ca.key \
    -days 3650 \
    -subj '/O=Redis Test/CN=Certificate Authority' \
    -out tests/tls/ca.crt

cat > tests/tls/openssl.cnf <<_END_
[ server_cert ]
keyUsage = digitalSignature, keyEncipherment
nsCertType = server
subjectAltName = @alt_names
[alt_names]
DNS.1 = redis-node-1
DNS.2 = redis-node-2
DNS.3 = redis-node-3
DNS.4 = redis-node-4
DNS.5 = redis-node-5
DNS.6 = redis-node-6
DNS.7 = localhost

IP.1 = 192.168.156.101
IP.2 = 192.168.156.102
IP.3 = 192.168.156.103
IP.4 = 192.168.156.104
IP.5 = 192.168.156.105
IP.6 = 192.168.156.106


[ client_cert ]
keyUsage = digitalSignature, keyEncipherment
nsCertType = client

_END_

generate_cert server "Server-only" "-extfile tests/tls/openssl.cnf -extensions server_cert"
generate_cert client "Client-only" "-extfile tests/tls/openssl.cnf -extensions client_cert"
generate_cert redis "Generic-cert"

[ -f tests/tls/redis.dh ] || openssl dhparam -out tests/tls/redis.dh 2048
