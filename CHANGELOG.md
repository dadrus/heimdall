# Changelog

## [0.6.1-alpha](https://github.com/dadrus/heimdall/compare/v0.6.0-alpha...v0.6.1-alpha) (2023-02-08)


### Bug Fixes

* Header matching case-sensitivity fixed ([#483](https://github.com/dadrus/heimdall/issues/483)) ([6d31d01](https://github.com/dadrus/heimdall/commit/6d31d011825dbc07dfad859f89903ddae159a2f6))
* Header value matching using wildcards fixed ([#485](https://github.com/dadrus/heimdall/issues/485)) ([cf3ed57](https://github.com/dadrus/heimdall/commit/cf3ed5774a109082723d8ab9c247ae7cc6c5a2b3))

## [0.6.0-alpha](https://github.com/dadrus/heimdall/compare/v0.5.0-alpha...v0.6.0-alpha) (2023-01-19)


### ⚠ BREAKING CHANGES

* `demo.enable` in helm chart renamed to `demo.enabled` ([#457](https://github.com/dadrus/heimdall/issues/457))
* Metrics service configuration changed ([#452](https://github.com/dadrus/heimdall/issues/452))
* New type for key store configuration introduced ([#434](https://github.com/dadrus/heimdall/issues/434))

### Features

* Helm chart supports setting of arbitrary environment variables ([#444](https://github.com/dadrus/heimdall/issues/444)) ([80de2ee](https://github.com/dadrus/heimdall/commit/80de2ee074a9a347a8da971cf9cfe924f281d3fa))
* New service exposing CPU, memory, etc profiling information ([#446](https://github.com/dadrus/heimdall/issues/446)) ([2175273](https://github.com/dadrus/heimdall/commit/217527307f6f45252a985a7b593214864f659143))
* Remaining validity of configured certificates exposed as metric ([#432](https://github.com/dadrus/heimdall/issues/432)) ([95b24f0](https://github.com/dadrus/heimdall/commit/95b24f0d2f0e61e5900d304f670d0b61d7075784))


### Bug Fixes

* Helm Chart fixed and does neither expect a heimdall config file, nor check for not existing property anymore ([#420](https://github.com/dadrus/heimdall/issues/420)) ([8a0c299](https://github.com/dadrus/heimdall/commit/8a0c29964752a8fbc88bccd3f55a669c037d91d9))
* Memory leak introduced by correlation between metrics & traces fixed ([#449](https://github.com/dadrus/heimdall/issues/449)) ([f00e0ec](https://github.com/dadrus/heimdall/commit/f00e0ec0a8d923fdd797a3b5b4d79d5ad59f4449))


### Code Refactoring

* `demo.enable` in helm chart renamed to `demo.enabled` ([#457](https://github.com/dadrus/heimdall/issues/457)) ([eb9c32e](https://github.com/dadrus/heimdall/commit/eb9c32eb5f4851775f9054b14ae951067044e9a7))
* Metrics service configuration changed ([#452](https://github.com/dadrus/heimdall/issues/452)) ([1b3a36e](https://github.com/dadrus/heimdall/commit/1b3a36e0eae3260aea75d8efef9112337edf1ba8))
* New type for key store configuration introduced ([#434](https://github.com/dadrus/heimdall/issues/434)) ([b2a9e58](https://github.com/dadrus/heimdall/commit/b2a9e581249373e7bdfb5dcab4dc942658143ab3))

## [0.5.0-alpha](https://github.com/dadrus/heimdall/compare/v0.4.1-alpha...v0.5.0-alpha) (2023-01-02)


### ⚠ BREAKING CHANGES

* Rule properties related to url matching moved to an own structure ([#402](https://github.com/dadrus/heimdall/issues/402))
* Templating support in redirect error handler mechanism ([#395](https://github.com/dadrus/heimdall/issues/395))
* Objects and functions available in templates and CEL expressions harmonized ([#394](https://github.com/dadrus/heimdall/issues/394))
* Configuration for keys & certificates harmonized ([#392](https://github.com/dadrus/heimdall/issues/392))
* Decision service returns `200 OK` instead of `202 Accepted` on success. ([#385](https://github.com/dadrus/heimdall/issues/385))
* Used HTTP status codes can be configured ([#383](https://github.com/dadrus/heimdall/issues/383))
* `mutator` renamed to `unifier` ([#375](https://github.com/dadrus/heimdall/issues/375))
* `hydrator` renamed to `contextualizer` ([#374](https://github.com/dadrus/heimdall/issues/374))
* `pipeline` config property renamed and moved into `rules` ([#370](https://github.com/dadrus/heimdall/issues/370))
* Local ECMAScript based authorizer is not supported any more ([#369](https://github.com/dadrus/heimdall/issues/369))
* Remote authorizer uses CEL instead of ECMAScript for response verification purposes ([#367](https://github.com/dadrus/heimdall/issues/367))

### Features

* Key material used for TLS can be password protected ([#392](https://github.com/dadrus/heimdall/issues/392)) ([e40c0a2](https://github.com/dadrus/heimdall/commit/e40c0a2e98fbf851759d268d1da1fa311c879847))
* New "local" authorizer which uses CEL expressions ([#364](https://github.com/dadrus/heimdall/issues/364)) ([d8988a8](https://github.com/dadrus/heimdall/commit/d8988a825112a4a962ddbd4f9a2c2f5e7a3d6929))
* Provider to load rule sets deployed in Kubernetes environments (incl. Helm Chart update) ([#336](https://github.com/dadrus/heimdall/issues/336)) ([dee229f](https://github.com/dadrus/heimdall/commit/dee229fc942ed05521221dbe390c23b090f4e7eb))
* Simple helm chart ([#325](https://github.com/dadrus/heimdall/issues/325)) ([23b4d5d](https://github.com/dadrus/heimdall/commit/23b4d5d93255229c95e22d38d2016e40be25ce94))
* Simpler endpoint configuration ([#376](https://github.com/dadrus/heimdall/issues/376)) ([248f483](https://github.com/dadrus/heimdall/commit/248f4835296fe95a30f7f36fe25513c822c225b9))
* Support for environment variables substitution in config file ([#381](https://github.com/dadrus/heimdall/issues/381)) ([5a6ec65](https://github.com/dadrus/heimdall/commit/5a6ec65a86af2809a83def265453332c0b6afaa7))
* Support for tracing and metrics correlation, as well as more metrics for go runtime information  ([#359](https://github.com/dadrus/heimdall/issues/359)) ([f34998a](https://github.com/dadrus/heimdall/commit/f34998a573c85170b3b74788af34bf7eb488862d))
* Templating support in redirect error handler mechanism ([#395](https://github.com/dadrus/heimdall/issues/395)) ([7a0eff3](https://github.com/dadrus/heimdall/commit/7a0eff39aa435c8e893e54a5b01de1328f6d24d7))
* Used HTTP status codes can be configured ([#383](https://github.com/dadrus/heimdall/issues/383)) ([5d46322](https://github.com/dadrus/heimdall/commit/5d4632246853895447a6363464afe431c0263e59))


### Bug Fixes

* `request_headers` error condition implementation fixed ([#373](https://github.com/dadrus/heimdall/issues/373)) ([a2d3045](https://github.com/dadrus/heimdall/commit/a2d3045da7ceb600268d5634459d98f2e3cd0626))
* Signer implementation fixed to take the first key from the key store if no key id was specified ([#392](https://github.com/dadrus/heimdall/issues/392)) ([e40c0a2](https://github.com/dadrus/heimdall/commit/e40c0a2e98fbf851759d268d1da1fa311c879847))


### Code Refactoring

* `hydrator` renamed to `contextualizer` ([#374](https://github.com/dadrus/heimdall/issues/374)) ([f20bc37](https://github.com/dadrus/heimdall/commit/f20bc37ceeda12b05b862f8190b3cba0e29e3577))
* `mutator` renamed to `unifier` ([#375](https://github.com/dadrus/heimdall/issues/375)) ([785b956](https://github.com/dadrus/heimdall/commit/785b9563b44667856d13b793edfcea55fb5e40ba))
* `pipeline` config property renamed and moved into `rules` ([#370](https://github.com/dadrus/heimdall/issues/370)) ([4234e54](https://github.com/dadrus/heimdall/commit/4234e5497512ba23300a740c9490d69c332b4b1b))
* Configuration for keys & certificates harmonized ([#392](https://github.com/dadrus/heimdall/issues/392)) ([e40c0a2](https://github.com/dadrus/heimdall/commit/e40c0a2e98fbf851759d268d1da1fa311c879847))
* Decision service returns `200 OK` instead of `202 Accepted` on success. ([#385](https://github.com/dadrus/heimdall/issues/385)) ([3460191](https://github.com/dadrus/heimdall/commit/346019162b0d938c689710885c1d8547e23e5dbf))
* Local ECMAScript based authorizer is not supported any more ([#369](https://github.com/dadrus/heimdall/issues/369)) ([db7febe](https://github.com/dadrus/heimdall/commit/db7febe8725b8c8bada4aebd2e4781a124f25dec))
* Objects and functions available in templates and CEL expressions harmonized ([#394](https://github.com/dadrus/heimdall/issues/394)) ([4ca9a9d](https://github.com/dadrus/heimdall/commit/4ca9a9d3ddb2f5cf723cbc1b729c8017622b3524))
* Remote authorizer uses CEL instead of ECMAScript for response verification purposes ([#367](https://github.com/dadrus/heimdall/issues/367)) ([92e1ffa](https://github.com/dadrus/heimdall/commit/92e1ffafec255d03bb3ec03b4eb66b37dd6d91c1))
* Rule properties related to url matching moved to an own structure ([#402](https://github.com/dadrus/heimdall/issues/402)) ([f3bd105](https://github.com/dadrus/heimdall/commit/f3bd105f65107f7864a843cc8d37be60fdeb57ae))

## [0.4.1-alpha](https://github.com/dadrus/heimdall/compare/v0.4.0-alpha...v0.4.1-alpha) (2022-11-11)


### Bug Fixes

* User for the heimdall process within the container fixed ([#323](https://github.com/dadrus/heimdall/issues/323)) ([77e36f9](https://github.com/dadrus/heimdall/commit/77e36f93009e82dae16f64c66fe905ed81162df9))

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
