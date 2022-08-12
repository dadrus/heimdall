# Changelog

## [0.2.0-alpha](https://github.com/dadrus/heimdall/compare/v0.1.0-alpha...v0.2.0-alpha) (2022-08-12)


### ⚠ BREAKING CHANGES

* `strip_prefix` in header authentication data strategy renamed to `schema` to reflect the actual mening and behavior (#129)
* "serve api" command renamed to "serve decision" (incl. wording in docs and logs) (#125)
* Make decision endpoint being available directly on the root (`/`) path of the decision service (#112)
* Usage of `trusted_proxies` is mandatory for Decision API to accept `X-Forwarded-*` headers (#111)
* Returning HTTP 404 instead of HTTP 500 if no default rule is configured and no rule matches (#96)

### Features

* Access log support ([#139](https://github.com/dadrus/heimdall/issues/139)) ([8387512](https://github.com/dadrus/heimdall/commit/8387512e166a38dea244fa3b15c0cdf318c2c603))
* Configurable fallback of authenticators even if the verification of the credentials fails ([#134](https://github.com/dadrus/heimdall/issues/134)) ([1336777](https://github.com/dadrus/heimdall/commit/1336777f5e537f5edf0fbc65695d31110d7c5794))
* Make decision endpoint being available directly on the root (`/`) path of the decision service ([#112](https://github.com/dadrus/heimdall/issues/112)) ([fa1ff5b](https://github.com/dadrus/heimdall/commit/fa1ff5b03bff0f1838c764fb8f4b77ac44652254))
* New `upstream` property introduced for the rule config to support reference of the upstream service for proxy mode ([0436a52](https://github.com/dadrus/heimdall/commit/0436a52bdfdf9a53c309bb4298eb74f2dcb2a0b0))
* New management service introduced, which exposes the health & jwks endpoints ([0436a52](https://github.com/dadrus/heimdall/commit/0436a52bdfdf9a53c309bb4298eb74f2dcb2a0b0))
* Not setting HTTP Server header anymore ([0436a52](https://github.com/dadrus/heimdall/commit/0436a52bdfdf9a53c309bb4298eb74f2dcb2a0b0))
* Remote authorizer optionally supports verification of responses from the remote system via a script ([#117](https://github.com/dadrus/heimdall/issues/117)) ([1ecabf0](https://github.com/dadrus/heimdall/commit/1ecabf01470e2e2c78bc0a03b20d1e893c5174d0))
* Retrieval of an access token from the request body ([#115](https://github.com/dadrus/heimdall/issues/115)) ([b336ab4](https://github.com/dadrus/heimdall/commit/b336ab4d18e700ca48566bfc6a6e147e0a3d3bb4))
* Returning HTTP 404 instead of HTTP 500 if no default rule is configured and no rule matches ([#96](https://github.com/dadrus/heimdall/issues/96)) ([0436a52](https://github.com/dadrus/heimdall/commit/0436a52bdfdf9a53c309bb4298eb74f2dcb2a0b0))
* Reverse proxy support ([#90](https://github.com/dadrus/heimdall/issues/90)) ([0436a52](https://github.com/dadrus/heimdall/commit/0436a52bdfdf9a53c309bb4298eb74f2dcb2a0b0))
* Usage of `trusted_proxies` is mandatory for Decision API to accept `X-Forwarded-*` headers ([#111](https://github.com/dadrus/heimdall/issues/111)) ([438932b](https://github.com/dadrus/heimdall/commit/438932bfec156a9f1a6c3a0576c8cc4700a6087c))


### Bug Fixes

* accesslog handler updated to include information about authenticated subject if present ([#162](https://github.com/dadrus/heimdall/issues/162)) ([3e286db](https://github.com/dadrus/heimdall/commit/3e286db68ceef41bc1527ef4f151048b93ca0be9))
* Basic Auth authenticator added to the schema and can now be configured ([#133](https://github.com/dadrus/heimdall/issues/133)) ([1336777](https://github.com/dadrus/heimdall/commit/1336777f5e537f5edf0fbc65695d31110d7c5794))
* basic_auth authenticator is not responsible for the request any more if the Authorization header does not contain Basic Auth schema ([#107](https://github.com/dadrus/heimdall/issues/107)) ([96136ef](https://github.com/dadrus/heimdall/commit/96136ef441eb413cd64ff1a3aba13a17b8be3627))
* Bearer token based authenticators do not feel responsible for the request anymore if no "Bearer" scheme is present in the "Authorization" header ([db5b773](https://github.com/dadrus/heimdall/commit/db5b7733e4e0b265b016891560bab35c7fd9dd29))
* Fixed usage of `X-Forwarded-Uri` header ([0436a52](https://github.com/dadrus/heimdall/commit/0436a52bdfdf9a53c309bb4298eb74f2dcb2a0b0))
* Handling and usage of the `upstream` property fixed (before this fix the proxy operation mode could not be used) ([#130](https://github.com/dadrus/heimdall/issues/130)) ([ed61e18](https://github.com/dadrus/heimdall/commit/ed61e18953a91c5a45235c96c73afcee4b0e4e00))
* jwt authenticator to not feel responsible if the bearer token is not in the JWT format ([#108](https://github.com/dadrus/heimdall/issues/108)) ([d8945c4](https://github.com/dadrus/heimdall/commit/d8945c4ab0abbe93b1350648d4f2964e7b5a8ab1))
* Schema fixed to allow TLS key & cert as well as CORS max_age configuration ([#122](https://github.com/dadrus/heimdall/issues/122)) ([58b6bc3](https://github.com/dadrus/heimdall/commit/58b6bc358cd5a433abc2d438ca74d0922b00ff84))
* trusted_proxy support added to the schema file to allow the validation of the corresponding property ([#105](https://github.com/dadrus/heimdall/issues/105)) ([556946e](https://github.com/dadrus/heimdall/commit/556946e53196f06a1d2cb530a7f24fb2b2e542e4))


### Code Refactoring

* "serve api" command renamed to "serve decision" (incl. wording in docs and logs) ([#125](https://github.com/dadrus/heimdall/issues/125)) ([e6aad0d](https://github.com/dadrus/heimdall/commit/e6aad0db622e5ddd3138501613f8a4f287e808f7))
* `strip_prefix` in header authentication data strategy renamed to `schema` to reflect the actual mening and behavior ([#129](https://github.com/dadrus/heimdall/issues/129)) ([f8a38ff](https://github.com/dadrus/heimdall/commit/f8a38ff4cdfba71c9fb65cc8744ef522f0c23412))

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
