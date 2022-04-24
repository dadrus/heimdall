# Heimdall
[![CI](https://github.com/dadrus/heimdall/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/dadrus/heimdall/actions/workflows/ci.yml)
[![Security-Scan](https://github.com/dadrus/heimdall/actions/workflows/trivy.yml/badge.svg)](https://github.com/dadrus/heimdall/actions/workflows/trivy.yml)
[![codecov](https://codecov.io/gh/dadrus/heimdall/branch/main/graph/badge.svg)](https://codecov.io/gh/dadrus/heimdall)

Heimdall is inspired by [Ory's OAthkeeper](https://www.ory.sh/docs/oathkeeper), tries however to resolve the functional limitations of that product by also building on a more modern technology stack resulting in a much simpler and faster implementation.

Heimdall authenticates and authorizes incoming HTTP requests as well as enriches these with further information and transforms resulting subject information to a format, both required by the upstream services. It is supposed to be used either as a Reverse Proxy in front of your upstream API or web server that rejects unauthorized requests and forwards authorized ones to your end points, or as a Decision API, which integrates with your API Gateway (Kong, NGNIX, Envoy, Traefik, etc) and then acts as a Policy Decision Point.

The current implementation is a pre alpha version, which alreay supports

* Decision API
* Loading rules from the file system
* Different authenticator types (allow, deny, jwt, oauth2 introspection, generic)
* Declarative authorizers (allow, deny)
* Mutators (opaque cookie, opaque header, jwt in the Authorization header) to transform the subject information
* Error Handlers (default, redirect, www-authenticate), which support accept type negotiation as well
* Opentracing support (jaeger & instana)
* key store in pem format for rsa-pss and ecdsa keys (pkcs#1 - plain only & pkcs#8 - plain and encrypted)
* Rules URL matching
* Flexible pipeline definition: authenticators+ -> any order(authorizer+, hydrator*) -> mutator+ -> error_handler+
* Optional default rule taking effect if no rule matches
* If Default rule is configured, the actual rule definition can reuse it (less yaml code)
* Typical execution time if caches are active is around 300µs (on my laptop)

Features to come are (more or less in this sequence):

* Hydrators - to enrich the subject information retrieved from the authenticator
* Authorizer (remote) - to make use of an external authorization system.
* X.509 certificates in key store
* jwks endpoint to let the upstream service verify the jwt signatures 
* Health & Readiness Probes
* k8s CRDs to load rules from.
* Reverse Proxy

