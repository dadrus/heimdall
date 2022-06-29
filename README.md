# Heimdall
[![CI](https://github.com/dadrus/heimdall/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/dadrus/heimdall/actions/workflows/ci.yml)
[![Security-Scan](https://github.com/dadrus/heimdall/actions/workflows/trivy.yaml/badge.svg)](https://github.com/dadrus/heimdall/actions/workflows/trivy.yml)
[![codecov](https://codecov.io/gh/dadrus/heimdall/branch/main/graph/badge.svg)](https://codecov.io/gh/dadrus/heimdall)
[![Go Report Card](https://goreportcard.com/badge/github.com/dadrus/heimdall)](https://goreportcard.com/report/github.com/dadrus/heimdall) 
[![License](https://img.shields.io/github/license/dadrus/heimdall)](https://github.com/dadrus/heimdall/blob/master/LICENSE)

Heimdall is inspired by the ZeroTrust idea and also by [Ory's OAthkeeper](https://www.ory.sh/docs/oathkeeper). Some experience with the latter and my inability to update it to include the desired functionality and behavior was the born hour of Heimdall. 

Heimdall authenticates and authorizes incoming HTTP requests as well as enriches these with further information and transforms resulting subject information to a format, required by the upstream services. It is supposed to be used either as a Reverse Proxy (not yet implemented) in front of your upstream API or web server that rejects unauthorized requests and forwards authorized ones to your end points, or as a Decision API, which integrates with your API Gateway (Kong, NGNIX, Envoy, Traefik, etc) and then acts as a Policy Decision Point.

Heimdall's main focus points beyond its functionality are:
* Performance - To achieve this, Heimdall makes use of [Fiber](https://gofiber.io/) and does not load or convert data during execution whenever possible. This is also true for reflection use.
* Clear abstractions - To allow extensibility and even replacement components if required, like e.g. of the currently used HTTP engine, and this without any side effects.
* Simplicity - To allow better understanding of code to everybody, who would like to contribute.

The current implementation is a pre alpha version, but already supports functionality listed below. A first alpha release will be available as soon as the test coverage hits 85% and all tasks for the [0.1.0-alpha](https://github.com/dadrus/heimdall/milestone/1) milestone are implemented.

* Decision API
* Loading rules from the file system
* Authenticator types (anonymous, basic-auth, generic, jwt, noop, oauth2 introspection, unauthorized)
* Authorizers (allow, deny, subject attributes (to evaluate available subject information by using JS) & remote (e.g. to communicate with open policy agent, ory keto, a zanzibar implementation, or any other authorization engine))
* Hydrators (generic) - to enrich the subject information retrieved from the authenticator
* Mutators (opaque cookie, opaque header, jwt in the Authorization header, noop) to transform the subject information
* Error Handlers (default, redirect, www-authenticate), which support accept type negotiation as well
* Opentracing support (jaeger & instana)
* Key store in pem format for rsa-pss and ecdsa keys (pkcs#1 - plain only & pkcs#8 - plain and encrypted)
* Rules URL matching
* Flexible pipeline definition: authenticators+ -> any order(authorizer*, hydrator*) -> mutator+ -> error_handler+
* Optional default rule taking effect if no rule matches
* If Default rule is configured, the actual rule definition can reuse it (less yaml code)
* Typical execution time if caches are active is around 300µs (on my laptop)
* The configuration is validated on startup. You can also validate it by making use of the "validate config" command.
* Health Probe

If you like to give it a try, checkout out the [documentation](https://dadrus.github.io/heimdall/docs/welcome/).
