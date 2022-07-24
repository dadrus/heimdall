# Changelog

## [0.1.1-alpha](https://github.com/dadrus/heimdall/compare/v0.1.0-alpha...v0.1.1-alpha) (2022-07-24)


### Bug Fixes

* basic_auth authenticator is not responsible for the request any more if the Authorization header does not contain Basic Auth schema ([#107](https://github.com/dadrus/heimdall/issues/107)) ([96136ef](https://github.com/dadrus/heimdall/commit/96136ef441eb413cd64ff1a3aba13a17b8be3627))
* jwt authenticator to not feel responsible if the bearer token is not in the JWT format ([#108](https://github.com/dadrus/heimdall/issues/108)) ([d8945c4](https://github.com/dadrus/heimdall/commit/d8945c4ab0abbe93b1350648d4f2964e7b5a8ab1))
* trusted_proxy support added to the schema file to allow the validation of the corresponding property ([#105](https://github.com/dadrus/heimdall/issues/105)) ([556946e](https://github.com/dadrus/heimdall/commit/556946e53196f06a1d2cb530a7f24fb2b2e542e4))

## [0.1.0-alpha](https://github.com/dadrus/heimdall/compare/v0.0.1-alpha...v0.1.0-alpha) (2022-07-19)

This is a very first release.

### Supported Features

* Decision API
* Loading rules from the file system
* Authenticator types (anonymous, basic-auth, generic, jwt, noop, oauth2 introspection, unauthorized)
* Authorizers (allow, deny, subject attributes (to evaluate available subject information by using JS) & remote (e.g. to communicate with open policy agent, ory keto, a zanzibar implementation, or any other authorization engine))
* Hydrators (generic) - to enrich the subject information retrieved from the authenticator
* Mutators (opaque cookie, opaque header, jwt in the Authorization header, noop) to transform the subject information
* Error Handlers (default, redirect, www-authenticate), which support accept type negotiation as well
* Opentracing support (jaeger & instana)
* Prometheus metrics
* Key store in pem format for rsa-pss and ecdsa keys (pkcs#1 - plain only & pkcs#8 - plain and encrypted)
* Rules URL matching
* Flexible pipeline definition: authenticators+ -> any order(authorizer*, hydrator*) -> mutator+ -> error_handler*
* Optional default rule taking effect if no rule matches
* If Default rule is configured, the actual rule definition can reuse it (less yaml code)
* Typical execution time if caches are active is around 300µs (on my laptop)
* The configuration is validated on startup. You can also validate it by making use of the "validate config" command.
* Health Probe
