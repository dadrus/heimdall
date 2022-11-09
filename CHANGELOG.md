# Changelog

## [0.4.0-alpha](https://github.com/dadrus/heimdall/compare/v0.3.0-alpha...v0.4.0-alpha) (2022-11-09)


### ⚠ BREAKING CHANGES

* file system provider rename (#281)
* OpenTelemetry tracing support (#246)
* Pipeline handler identifier are present in error context to support pipeline handler specific error handling strategies (#239)
* ECDSA P-384 key is generated instead of RSA-2048 for JWT signing purposes on startup if no key store has been configured

### Features

* Configuration of minimal allowed TLS version and the required cipher suites ([#303](https://github.com/dadrus/heimdall/issues/303)) ([76c02bf](https://github.com/dadrus/heimdall/commit/76c02bfc69f807ec59e2add191e817790d195b8b))
* HTTP caching according to RFC 7234 is supported by pipeline handlers and the httpendpoint provider ([#307](https://github.com/dadrus/heimdall/issues/307)) ([c5349c1](https://github.com/dadrus/heimdall/commit/c5349c1e41459e63242abe87b3305a0a73bc23c5))
* Made all log statements adhering to GELF format ([#259](https://github.com/dadrus/heimdall/issues/259)) ([94bf2f1](https://github.com/dadrus/heimdall/commit/94bf2f14fca62b93de3f2096b15e3fb75e423c61))
* OpenTelemetry tracing support ([#246](https://github.com/dadrus/heimdall/issues/246)) ([c3e81fd](https://github.com/dadrus/heimdall/commit/c3e81fd3d5ce2af1db24288275128d3f55c5f060))
* Pipeline handler identifier are present in error context to support pipeline handler specific error handling strategies ([#239](https://github.com/dadrus/heimdall/issues/239)) ([8a73e86](https://github.com/dadrus/heimdall/commit/8a73e863fde79cc568ae7d77d8b9433a4c14b738))
* Provider to load rule sets from cloud blobs ([#283](https://github.com/dadrus/heimdall/issues/283)) ([6eef3dc](https://github.com/dadrus/heimdall/commit/6eef3dc6857414a56d8e76999d8e518aca5a0867))
* Provider to load rule sets from HTTP(s) endpoints ([#263](https://github.com/dadrus/heimdall/issues/263)) ([5ff495c](https://github.com/dadrus/heimdall/commit/5ff495cb4ad4a32314f44c92b7b8035a44212ecd))
* Support for log, trace and request correlation ([#254](https://github.com/dadrus/heimdall/issues/254)) ([a543230](https://github.com/dadrus/heimdall/commit/a5432307b7eb842187277013bc7f3445923df37d))


### Code Refactoring

* ECDSA P-384 key is generated instead of RSA-2048 for JWT signing purposes on startup if no key store has been configured ([6b62b47](https://github.com/dadrus/heimdall/commit/6b62b4782c2c5e6fd26809e2e7baaad22325f005))
* file system provider rename ([#281](https://github.com/dadrus/heimdall/issues/281)) ([04a33f2](https://github.com/dadrus/heimdall/commit/04a33f22efc97f22de0cf43b9ffe5a5976dd4e39))

## [0.3.0-alpha](https://github.com/dadrus/heimdall/compare/v0.2.0-alpha...v0.3.0-alpha) (2022-09-09)


### ⚠ BREAKING CHANGES

* Prefix for considered environment variables renamed from `HEIMDALL_` to `HEIMDALLCFG_` and made this prefix configurable via a `--env-config-prefix` flag (#220)
* `session` property used by some authenticators renamed (incl. its properties) to `subject` to better reflect its meaning (#200)
* `jwt_from` property of the `jwt_authenticator` renamed to `jwt_source` to comply with naming in other authenticators (#199)

### Features

* `generic` authenticator updated to consider ttl of the session object received from the `identity_info_endpoint` and to enable session validation ([#201](https://github.com/dadrus/heimdall/issues/201)) ([42b4e6c](https://github.com/dadrus/heimdall/commit/42b4e6c4852fa3d46009241e08310c413de5437f))
* `jwt_authenticator` updated to support X.509 certificates (incl validation) in JWKs used for JWT signature verification ([#172](https://github.com/dadrus/heimdall/issues/172)) ([19ef20d](https://github.com/dadrus/heimdall/commit/19ef20daa1964e82389db05b6aae2cf56b3321ca))
* `oauth2_authenticator` updated to optionally support token source selection, like specific header, schema, etc ([#198](https://github.com/dadrus/heimdall/issues/198)) ([e7ad797](https://github.com/dadrus/heimdall/commit/e7ad797c83cca5b9b58b1fddb88b62a94ed9cfda))
* If no `kid` is present in the JWT, the `jwt_authenticator` can now iterate over the received JWKS and try to verify the signature until one of the keys matches ([#196](https://github.com/dadrus/heimdall/issues/196)) ([488e46f](https://github.com/dadrus/heimdall/commit/488e46f67c1b0231e3c8127e0bd560f52d8eb2a8))
* x509 certificate support in keystore ([#166](https://github.com/dadrus/heimdall/issues/166)) ([2d9af4c](https://github.com/dadrus/heimdall/commit/2d9af4c00e258cc696cceb2c6e184086c0744d3e))


### Bug Fixes

* Prefix for considered environment variables renamed from `HEIMDALL_` to `HEIMDALLCFG_` and made this prefix configurable via a `--env-config-prefix` flag ([#220](https://github.com/dadrus/heimdall/issues/220)) ([3bfeff1](https://github.com/dadrus/heimdall/commit/3bfeff159a58896c4c6785e3889e986879866a9b))


### Code Refactoring

* `jwt_from` property of the `jwt_authenticator` renamed to `jwt_source` to comply with naming in other authenticators ([#199](https://github.com/dadrus/heimdall/issues/199)) ([29d6bcb](https://github.com/dadrus/heimdall/commit/29d6bcb5959b21713564492d6f144dec1eed99f6))
* `session` property used by some authenticators renamed (incl. its properties) to `subject` to better reflect its meaning ([#200](https://github.com/dadrus/heimdall/issues/200)) ([869d8ae](https://github.com/dadrus/heimdall/commit/869d8ae327e94dca87202541f044882054a9ea2b))

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
