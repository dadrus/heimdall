# Changelog

## [0.13.0-alpha](https://github.com/dadrus/heimdall/compare/v0.12.0-alpha...v0.13.0-alpha) (2024-01-03)


### ⚠ BREAKING CHANGES

* Endpoint specific HTTP cache settings refactored to allow HTTP cache ttl definition ([#1043](https://github.com/dadrus/heimdall/issues/1043))

### Features

* OAuth2/OIDC metadata discovery for `jwt` authenticator ([#1043](https://github.com/dadrus/heimdall/issues/1043)) ([2dbfa5f](https://github.com/dadrus/heimdall/commit/2dbfa5f49bf7611e41992d6946fe77a34cd237d3))
* OAuth2/OIDC metadata discovery for `oauth2_introspection` authenticator ([#1043](https://github.com/dadrus/heimdall/issues/1043)) ([2dbfa5f](https://github.com/dadrus/heimdall/commit/2dbfa5f49bf7611e41992d6946fe77a34cd237d3))


### Code Refactorings

* Endpoint specific HTTP cache settings refactored to allow HTTP cache ttl definition ([#1043](https://github.com/dadrus/heimdall/issues/1043)) ([2dbfa5f](https://github.com/dadrus/heimdall/commit/2dbfa5f49bf7611e41992d6946fe77a34cd237d3))


### Bug Fixes

* Accept header usage ([#1107](https://github.com/dadrus/heimdall/issues/1107)) ([f738ee8](https://github.com/dadrus/heimdall/commit/f738ee80220e35e4c361437d86ccdab9f5a894c5))
* Setting of binary artifacts version fixed ([#1087](https://github.com/dadrus/heimdall/issues/1087)) ([f7dbbee](https://github.com/dadrus/heimdall/commit/f7dbbee5ecc42b9182ef164c6c76ad09807d666f))


### Dependencies

* update golang to 1.21.5 ([#1082](https://github.com/dadrus/heimdall/issues/1082)) ([a996ce7](https://github.com/dadrus/heimdall/commit/a996ce78d7f28a390190a7c7a04262dc370782f2))
* update golang.org/x/exp digest to 02704c9 ([#1111](https://github.com/dadrus/heimdall/issues/1111)) ([1e18000](https://github.com/dadrus/heimdall/commit/1e18000557ebf023a596b5379ef10413d2192f16))
* update google.golang.org/genproto/googleapis/rpc digest to 50ed04b ([#1115](https://github.com/dadrus/heimdall/issues/1115)) ([eda1d2d](https://github.com/dadrus/heimdall/commit/eda1d2d48b8163fbcb442ed191f425c2cb4ad7b5))
* update kubernetes packages to v0.29.0 ([#1100](https://github.com/dadrus/heimdall/issues/1100)) ([65b3619](https://github.com/dadrus/heimdall/commit/65b361936ca417972b91bd432a87a09008673810))
* update module github.com/envoyproxy/go-control-plane to v0.12.0 ([#1117](https://github.com/dadrus/heimdall/issues/1117)) ([7fbb737](https://github.com/dadrus/heimdall/commit/7fbb737308bb6272423f66b6793aaa5c3a046e32))
* update module github.com/go-co-op/gocron/v2 to v2.1.2 ([#1116](https://github.com/dadrus/heimdall/issues/1116)) ([13505da](https://github.com/dadrus/heimdall/commit/13505daf736278beadf36fc6c67534a894ed2b75))
* update module github.com/google/uuid to v1.5.0 ([#1097](https://github.com/dadrus/heimdall/issues/1097)) ([5273ac8](https://github.com/dadrus/heimdall/commit/5273ac8008263393027b29a04534d96028445bb7))
* update module github.com/jellydator/ttlcache/v3 to v3.1.1 ([#1102](https://github.com/dadrus/heimdall/issues/1102)) ([90dcc4d](https://github.com/dadrus/heimdall/commit/90dcc4db63d872f86e4c0ac4b3ce9dc7ceeee7d4))
* update module github.com/prometheus/client_golang to v1.18.0 ([#1112](https://github.com/dadrus/heimdall/issues/1112)) ([57da7ec](https://github.com/dadrus/heimdall/commit/57da7ecd5b47ece03faadc5215546c02434aadbe))
* update module gocloud.dev to v0.36.0 ([#1113](https://github.com/dadrus/heimdall/issues/1113)) ([584d51f](https://github.com/dadrus/heimdall/commit/584d51f8f0afdfc3e64fc85a4e107e73c2f6ddf1))
* update module google.golang.org/grpc to v1.60.1 ([#1105](https://github.com/dadrus/heimdall/issues/1105)) ([329f647](https://github.com/dadrus/heimdall/commit/329f647a7047e8a2027296f1686d2760ef3cde24))
* update module google.golang.org/protobuf to v1.32.0 ([#1109](https://github.com/dadrus/heimdall/issues/1109)) ([47d7785](https://github.com/dadrus/heimdall/commit/47d77852d7840c82f29eb2db460bb6f930b5ddfd))

## [0.12.0-alpha](https://github.com/dadrus/heimdall/compare/v0.11.1-alpha...v0.12.0-alpha) (2023-11-29)


### ⚠ BREAKING CHANGES

* Support for `X-Forwarded-Path` header dropped ([#1073](https://github.com/dadrus/heimdall/issues/1073))
* `if` conditional statements for error pipeline mechanisms ([#1055](https://github.com/dadrus/heimdall/issues/1055))
* `Request.ClientIP` renamed to `Request.ClientIPAddresses` to reflect the actual contents ([#1066](https://github.com/dadrus/heimdall/issues/1066))
* The term "scheme" is used properly as defined by RFC9110 ([#1042](https://github.com/dadrus/heimdall/issues/1042))
* Rule(-Set) related configuration properties `mechanisms` , `default` and `providers` moved one level up and renamed ([#1028](https://github.com/dadrus/heimdall/issues/1028))
* Support for `noop` authenticator removed ([#1015](https://github.com/dadrus/heimdall/issues/1015))
* Endpoint specific `client_credentials` auth strategy renamed to `oauth2_client_credentials` ([#975](https://github.com/dadrus/heimdall/issues/975))
* `unifier` renamed to `finalizer` ([#956](https://github.com/dadrus/heimdall/issues/956))
* Support for OTEL metrics ([#948](https://github.com/dadrus/heimdall/issues/948))
* Proxy implementation migrated from fiber to stdlib http package ([#889](https://github.com/dadrus/heimdall/issues/889))
* Support for OpenTelemetry Jaeger exporter dropped (It has been deprecated by Jaeger back in 2022) ([#884](https://github.com/dadrus/heimdall/issues/884))

### Features

* `client_credentials` authentication strategy for `Endpoint` enhanced to support the same options as the corresponding finalizer ([#971](https://github.com/dadrus/heimdall/issues/971)) ([ec16d5d](https://github.com/dadrus/heimdall/commit/ec16d5de59196ca95c7e8dd34a5ccbc8e97b4b9b))
* `finalizers` are optional ([#1027](https://github.com/dadrus/heimdall/issues/1027)) ([864c879](https://github.com/dadrus/heimdall/commit/864c879f386316b6aebd294268527c179de2ac9e))
* `if` conditional statements for error pipeline mechanisms ([#1055](https://github.com/dadrus/heimdall/issues/1055)) ([7cf97dc](https://github.com/dadrus/heimdall/commit/7cf97dca57e0272efa5cc851a67a8ef27279bc1b))
* Access to request body in templates and CEL expressions ([#1069](https://github.com/dadrus/heimdall/issues/1069)) ([69dd7d2](https://github.com/dadrus/heimdall/commit/69dd7d2a35de15071be0c869bc81e8150b2e5f62))
* Container images are published to GHCR in addition to DockerHub ([#1041](https://github.com/dadrus/heimdall/issues/1041)) ([04b1066](https://github.com/dadrus/heimdall/commit/04b106631d8db2e22b1f8d167091ab2e52eb28c2))
* Helm chart pulls heimdall container image from ghcr.io instead from DockerHub ([#1053](https://github.com/dadrus/heimdall/issues/1053)) ([b3c729a](https://github.com/dadrus/heimdall/commit/b3c729a16742890f99bdca93073ee4499a4588f6))
* HTTP 2.0 support ([#889](https://github.com/dadrus/heimdall/issues/889)) ([ffcccf6](https://github.com/dadrus/heimdall/commit/ffcccf68b733c614c803f09fc50eea8e9afe1b84))
* Kubernetes RuleSet resource deployment/usage status ([#987](https://github.com/dadrus/heimdall/issues/987)) ([738e3ec](https://github.com/dadrus/heimdall/commit/738e3ecfe89e37fc988d5d71cc80d0e9001ac136))
* New `oauth2_client_credentials` finalizer ([#959](https://github.com/dadrus/heimdall/issues/959)) ([4c9f807](https://github.com/dadrus/heimdall/commit/4c9f807147b64ea301cac0a6fc44ee08610898e9))
* New `trace` log level allowing dumping HTTP requests, responses and the current Subject contents ([#877](https://github.com/dadrus/heimdall/issues/877)) ([512f1ed](https://github.com/dadrus/heimdall/commit/512f1ed42a792db8b43f7f6c30e9e0ffe8542c61))
* Opt-In for url-encoded slashes in URL paths ([#1071](https://github.com/dadrus/heimdall/issues/1071)) ([96bb188](https://github.com/dadrus/heimdall/commit/96bb1883f09c8d7017752b50e012aa6392e658c0))
* Release archive contains an SBOM in CycloneDX (json) format ([#867](https://github.com/dadrus/heimdall/issues/867)) ([d8a7cff](https://github.com/dadrus/heimdall/commit/d8a7cff8600a3873805aafb40c6cf60202c32320))
* RuleSet version increased to `1alpha3`, respectively to `v1alpha3` in k8s CRD ([#1054](https://github.com/dadrus/heimdall/issues/1054)) ([943c9ce](https://github.com/dadrus/heimdall/commit/943c9ce7e2777fdc8b4f806ae48ba5f8ac9fb16d))
* SBOM and attestations for published container images ([#868](https://github.com/dadrus/heimdall/issues/868)) ([3564870](https://github.com/dadrus/heimdall/commit/3564870d09d4bdc93e826ce2fb32860621ac69a8))
* SSE support ([#889](https://github.com/dadrus/heimdall/issues/889)) ([ffcccf6](https://github.com/dadrus/heimdall/commit/ffcccf68b733c614c803f09fc50eea8e9afe1b84))
* Support for OTEL metrics ([#948](https://github.com/dadrus/heimdall/issues/948)) ([eeb5a82](https://github.com/dadrus/heimdall/commit/eeb5a82dc754a24972cb295d7313b199de0a7f43))
* Templating support in `remote` authorizer and `generic` contextualizer `values` property ([#1047](https://github.com/dadrus/heimdall/issues/1047)) ([2835faa](https://github.com/dadrus/heimdall/commit/2835faab03ebb2f27aa3ce826fec249375de19e4))
* Validating admission controller for RuleSet resources ([#984](https://github.com/dadrus/heimdall/issues/984)) ([3357e57](https://github.com/dadrus/heimdall/commit/3357e57a64abde9299339a727690db845998d4bd))
* WebSockets support ([#889](https://github.com/dadrus/heimdall/issues/889)) ([ffcccf6](https://github.com/dadrus/heimdall/commit/ffcccf68b733c614c803f09fc50eea8e9afe1b84))


### Code Refactorings

* `Request.ClientIP` renamed to `Request.ClientIPAddresses` to reflect the actual contents ([#1066](https://github.com/dadrus/heimdall/issues/1066)) ([0f9484f](https://github.com/dadrus/heimdall/commit/0f9484f9d9646c0b830a682531305fb34b84fe1b))
* `unifier` renamed to `finalizer` ([#956](https://github.com/dadrus/heimdall/issues/956)) ([d54e39d](https://github.com/dadrus/heimdall/commit/d54e39d3cd365b234e38ae49a193abfa4a347c99))
* Endpoint specific `client_credentials` auth strategy renamed to `oauth2_client_credentials` ([#975](https://github.com/dadrus/heimdall/issues/975)) ([b11005c](https://github.com/dadrus/heimdall/commit/b11005c5f33d70e6df1874c18e44dbddc5687b89))
* Proxy implementation migrated from fiber to stdlib http package ([#889](https://github.com/dadrus/heimdall/issues/889)) ([ffcccf6](https://github.com/dadrus/heimdall/commit/ffcccf68b733c614c803f09fc50eea8e9afe1b84))
* Rule(-Set) related configuration properties `mechanisms` , `default` and `providers` moved one level up and renamed ([#1028](https://github.com/dadrus/heimdall/issues/1028)) ([f6ce3b8](https://github.com/dadrus/heimdall/commit/f6ce3b88a7d7193dcb2365a3ce0772f9504ee4eb))
* Support for `noop` authenticator removed ([#1015](https://github.com/dadrus/heimdall/issues/1015)) ([8cb3bd3](https://github.com/dadrus/heimdall/commit/8cb3bd3777afa0f53c602782e1fa282309ea7fee))
* Support for `X-Forwarded-Path` header dropped ([#1073](https://github.com/dadrus/heimdall/issues/1073)) ([342c11a](https://github.com/dadrus/heimdall/commit/342c11a4123700928b5a3793685e0b08bb56a659))
* Support for OpenTelemetry Jaeger exporter dropped (It has been deprecated by Jaeger back in 2022) ([#884](https://github.com/dadrus/heimdall/issues/884)) ([97b81b1](https://github.com/dadrus/heimdall/commit/97b81b199c1d0250ca94a99d61e701b1f482328c))


### Bug Fixes

* HTTP method expansion in k8s RuleSet resources ([#1005](https://github.com/dadrus/heimdall/issues/1005)) ([861c2b6](https://github.com/dadrus/heimdall/commit/861c2b6273ff0971013d1120ed463d0f5d230e1b))
* Kubernetes RuleSet resource is unloaded by heimdall on authClassName mismatch ([#987](https://github.com/dadrus/heimdall/issues/987)) ([738e3ec](https://github.com/dadrus/heimdall/commit/738e3ecfe89e37fc988d5d71cc80d0e9001ac136))
* Making use of better constraints in the definition of the RuleSet CRD to not exceed the k8s rule cost budget ([#1004](https://github.com/dadrus/heimdall/issues/1004)) ([7d71351](https://github.com/dadrus/heimdall/commit/7d71351188d88774f609f0996c8de689833392e3))
* MIME type decoder covers optional parameters ([#1057](https://github.com/dadrus/heimdall/issues/1057)) ([c1c088c](https://github.com/dadrus/heimdall/commit/c1c088c105942af0f614e7869b15a17bedb5e31f))
* The term "scheme" is used properly as defined by RFC9110 ([#1042](https://github.com/dadrus/heimdall/issues/1042)) ([aaf4bd3](https://github.com/dadrus/heimdall/commit/aaf4bd351dbf8feaccdd5705e748931a6b759d84))


### Documentation

* Integration guide and demo for (Ambassador) emissary ingress controller ([#838](https://github.com/dadrus/heimdall/issues/838)) ([456cfd5](https://github.com/dadrus/heimdall/commit/456cfd5c4dad6a4c972679882ae9071299608d65))
* Integration guide and demo for HAProxy ingress controller ([#837](https://github.com/dadrus/heimdall/issues/837)) ([3766fa2](https://github.com/dadrus/heimdall/commit/3766fa2093aa5c612a547bdd7d71097f638256ff))
* New landing page ([#853](https://github.com/dadrus/heimdall/issues/853)) ([fc2a337](https://github.com/dadrus/heimdall/commit/fc2a337b77dbed96a837122cbdb6480323b32c1d))
* New sections describing signature verification of released archives, container images and the SBOM. ([#872](https://github.com/dadrus/heimdall/issues/872)) ([8f42c24](https://github.com/dadrus/heimdall/commit/8f42c240026cb5e32d305168b2d265c9c2b50d6b))


### Dependencies

* update golang to 1.21.4 ([79a0106](https://github.com/dadrus/heimdall/commit/79a01060864fea27ab5709eaa096461cc26b5fc0))
* update golang.org/x/exp digest to 6522937 ([#1068](https://github.com/dadrus/heimdall/issues/1068)) ([83827ae](https://github.com/dadrus/heimdall/commit/83827ae38c9f8274555cb652b0f6a35b06230ae2))
* update google.golang.org/genproto/googleapis/rpc digest to 3a041ad ([#1067](https://github.com/dadrus/heimdall/issues/1067)) ([431fd89](https://github.com/dadrus/heimdall/commit/431fd89fb9312331fd3577c75a4ff1653e717e7b))
* update kubernetes packages to v0.28.4 ([#1040](https://github.com/dadrus/heimdall/issues/1040)) ([312ace1](https://github.com/dadrus/heimdall/commit/312ace19ad97a4c54c6e066290faf1823d876b09))
* update module github.com/felixge/httpsnoop to v1.0.4 ([#995](https://github.com/dadrus/heimdall/issues/995)) ([10006e5](https://github.com/dadrus/heimdall/commit/10006e54c6dde8809b5a25216a0eb236987ef41b))
* update module github.com/fsnotify/fsnotify to v1.7.0 ([#981](https://github.com/dadrus/heimdall/issues/981)) ([4c7bd90](https://github.com/dadrus/heimdall/commit/4c7bd90e134bd36e04f2bb82cca87a82d3803502))
* update module github.com/go-co-op/gocron to v1.36.0 ([#1013](https://github.com/dadrus/heimdall/issues/1013)) ([dd44dc2](https://github.com/dadrus/heimdall/commit/dd44dc2bb7446b32cd2bca87c59be31529503a03))
* update module github.com/google/cel-go to v0.18.2 ([#1016](https://github.com/dadrus/heimdall/issues/1016)) ([d4e6d6f](https://github.com/dadrus/heimdall/commit/d4e6d6f64bb9d1ef013cc001bb1cbd9fd800d36d))
* update module github.com/google/uuid to v1.4.0 ([#985](https://github.com/dadrus/heimdall/issues/985)) ([0d9666d](https://github.com/dadrus/heimdall/commit/0d9666d0812aef7173e2d0f6681c40fd42a98435))
* update module github.com/grpc-ecosystem/go-grpc-middleware/v2 to v2.0.1 ([#930](https://github.com/dadrus/heimdall/issues/930)) ([06697fe](https://github.com/dadrus/heimdall/commit/06697fedabe069b1c4d515e37061865c467b85fc))
* update module github.com/jellydator/ttlcache/v3 to v3.1.0 ([#870](https://github.com/dadrus/heimdall/issues/870)) ([9afd7c4](https://github.com/dadrus/heimdall/commit/9afd7c469cce8c00b32478f1b9b911e8bd5c4258))
* update module github.com/rs/zerolog to v1.31.0 ([#936](https://github.com/dadrus/heimdall/issues/936)) ([39f9b30](https://github.com/dadrus/heimdall/commit/39f9b30d81bb5401185cad755094907eda2f9baa))
* update module github.com/spf13/cobra to v1.8.0 ([#997](https://github.com/dadrus/heimdall/issues/997)) ([fb0bbe5](https://github.com/dadrus/heimdall/commit/fb0bbe55035f8c2cbc30846d5386d4935066bbd6))
* update module github.com/tidwall/gjson to v1.17.0 ([#934](https://github.com/dadrus/heimdall/issues/934)) ([8866dba](https://github.com/dadrus/heimdall/commit/8866dbab4cb29729fe50ff805cc2ba26dc3d8350))
* update module github.com/tonglil/opentelemetry-go-datadog-propagator to v0.1.1 ([#890](https://github.com/dadrus/heimdall/issues/890)) ([92196e1](https://github.com/dadrus/heimdall/commit/92196e1b140566fd8f644860dc7cf85922761912))
* update module github.com/wi2l/jsondiff to v0.5.0 ([#1024](https://github.com/dadrus/heimdall/issues/1024)) ([db99a7c](https://github.com/dadrus/heimdall/commit/db99a7c9781335ae275fa93089aa2df1ad3ab82f))
* update module go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc to v0.46.1 ([#1045](https://github.com/dadrus/heimdall/issues/1045)) ([1615f40](https://github.com/dadrus/heimdall/commit/1615f4002b17577c59916b54b5f691c788f08802))
* update module go.opentelemetry.io/contrib/instrumentation/host to v0.46.1 ([#1045](https://github.com/dadrus/heimdall/issues/1045)) ([1615f40](https://github.com/dadrus/heimdall/commit/1615f4002b17577c59916b54b5f691c788f08802))
* update module go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp to v0.46.1 ([#1045](https://github.com/dadrus/heimdall/issues/1045)) ([1615f40](https://github.com/dadrus/heimdall/commit/1615f4002b17577c59916b54b5f691c788f08802))
* update module go.opentelemetry.io/contrib/instrumentation/runtime to v0.46.1 ([#1045](https://github.com/dadrus/heimdall/issues/1045)) ([1615f40](https://github.com/dadrus/heimdall/commit/1615f4002b17577c59916b54b5f691c788f08802))
* update module go.opentelemetry.io/contrib/propagators/autoprop to v0.46.1 ([#1045](https://github.com/dadrus/heimdall/issues/1045)) ([1615f40](https://github.com/dadrus/heimdall/commit/1615f4002b17577c59916b54b5f691c788f08802))
* update module go.uber.org/fx to v1.20.1 ([#978](https://github.com/dadrus/heimdall/issues/978)) ([98f67a0](https://github.com/dadrus/heimdall/commit/98f67a0d64e56ea18a859778b48517fd0dbc6c8f))
* update module gocloud.dev to v0.34.0 ([#879](https://github.com/dadrus/heimdall/issues/879)) ([25ae833](https://github.com/dadrus/heimdall/commit/25ae833f439737fcf7ba61d8b0a4e6e3ba95fbca))
* update module google.golang.org/grpc to v1.59.0 ([#977](https://github.com/dadrus/heimdall/issues/977)) ([9211fae](https://github.com/dadrus/heimdall/commit/9211faeee037434b013182f753e9d52e38479086))
* update module k8s.io/klog/v2 to v2.110.1 ([#994](https://github.com/dadrus/heimdall/issues/994)) ([e1b655a](https://github.com/dadrus/heimdall/commit/e1b655af3fa425b1892a5c127c64859f5b34d032))
* update opentelemetry-go monorepo to v1.21.0 ([#1045](https://github.com/dadrus/heimdall/issues/1045)) ([1615f40](https://github.com/dadrus/heimdall/commit/1615f4002b17577c59916b54b5f691c788f08802))

## [0.11.1-alpha](https://github.com/dadrus/heimdall/compare/v0.11.0-alpha...v0.11.1-alpha) (2023-08-08)


### Bug Fixes

* Usage of `X-Forwarded-*` headers enhanced security wise ([#839](https://github.com/dadrus/heimdall/issues/839)) ([cd4f7e8](https://github.com/dadrus/heimdall/commit/cd4f7e8b603992831a1bd617f6853751574fd016))
* Fix for wrong HTTP scheme used while matching the rules if heimdall is operated over TLS ([#839](https://github.com/dadrus/heimdall/issues/839)) ([cd4f7e8](https://github.com/dadrus/heimdall/commit/cd4f7e8b603992831a1bd617f6853751574fd016))

### Documentation

* Available integration guides updated to describe secure integration options only ([#839](https://github.com/dadrus/heimdall/issues/839)) ([cd4f7e8](https://github.com/dadrus/heimdall/commit/cd4f7e8b603992831a1bd617f6853751574fd016)


### Dependencies

* update golang.org/x/exp digest to 050eac2 ([#842](https://github.com/dadrus/heimdall/issues/842)) ([964a867](https://github.com/dadrus/heimdall/commit/964a867aa689f57dbb6e92b78d7d05e1fb1a1acf))
* update google.golang.org/genproto/googleapis/rpc digest to 1744710 ([#841](https://github.com/dadrus/heimdall/issues/841)) ([8f5c5e3](https://github.com/dadrus/heimdall/commit/8f5c5e3f5e9276a57ead596e370c65b5668dbb16))

## [0.11.0-alpha](https://github.com/dadrus/heimdall/compare/v0.10.1-alpha...v0.11.0-alpha) (2023-08-04)


### ⚠ BREAKING CHANGES

* `values` property for endpoint teplating must be configured on the mechanism conf level ([#746](https://github.com/dadrus/heimdall/issues/746))

### Features

* Helm chart allows usage of optionall volumes and volume mounts ([#825](https://github.com/dadrus/heimdall/issues/825)) ([0ed2cf0](https://github.com/dadrus/heimdall/commit/0ed2cf0c54faa904fcbbfcbba03295a8c4df0606))
* Helm chart enhanced to allow passing optional arguments to heimdall ([#824](https://github.com/dadrus/heimdall/issues/824)) ([9b0149d](https://github.com/dadrus/heimdall/commit/9b0149dc041cb95161a4db86f8d30efe99d9b86a))
* HTTP method expansion with placeholder key words ([#774](https://github.com/dadrus/heimdall/issues/774)) ([d25be3b](https://github.com/dadrus/heimdall/commit/d25be3b8a3504f229841476392a650cf97fded73))
* New CEL and template functions to ease access to different parts of the request and beyond ([#689](https://github.com/dadrus/heimdall/issues/689)) ([730b220](https://github.com/dadrus/heimdall/commit/730b2206fdfc688ca42bcdf0e344d8fa6bfba232))
* Support of env variables in rule sets loaded by the `file_system` provider using Bash syntax ([#775](https://github.com/dadrus/heimdall/issues/775)) ([6fa6415](https://github.com/dadrus/heimdall/commit/6fa6415da12ede1285ffbe9e9c58a774036c5f05))
* Values object can be used in payload of generic contextualizer and remote authorizer ([#749](https://github.com/dadrus/heimdall/issues/749)) ([42267cb](https://github.com/dadrus/heimdall/commit/42267cbc074049be92dfb5ad205236691900399a))


### Code Refactorings

* `values` property for endpoint teplating must be configured on the mechanism conf level ([#746](https://github.com/dadrus/heimdall/issues/746)) ([9809fe4](https://github.com/dadrus/heimdall/commit/9809fe4d9bb6c5161af1fe47887dafcb2eaefa89))


### Bug Fixes

* Loading of structured configuration from env variables ([#768](https://github.com/dadrus/heimdall/issues/768)) ([a76c722](https://github.com/dadrus/heimdall/commit/a76c722072640ddb628f2a8f2ba48fe7ab53e360))
* Quoting configured env vars in helm chart ([#827](https://github.com/dadrus/heimdall/issues/827)) ([b4eeb96](https://github.com/dadrus/heimdall/commit/b4eeb962c55aa06cdebae0febc4aba248cf74995))
* Validation of a self-signed certificate does not require its presence in the system wide trust store any more ([#830](https://github.com/dadrus/heimdall/issues/830)) ([56a2d1f](https://github.com/dadrus/heimdall/commit/56a2d1f33fd0c207dbda0eb033ec02a66684818a))


### Documentation

* New integration guide for Contour ingress controller ([#828](https://github.com/dadrus/heimdall/issues/828)) ([ea62e91](https://github.com/dadrus/heimdall/commit/ea62e9195f3516b6a70a67bd4b475ec3f7bf99e7))
* Proxy buffer sizes example fixed ([#814](https://github.com/dadrus/heimdall/issues/814)) ([6867822](https://github.com/dadrus/heimdall/commit/68678228af37e21e11273cbdc88f5326494ef8c5))

## [0.10.1-alpha](https://github.com/dadrus/heimdall/compare/v0.10.0-alpha...v0.10.1-alpha) (2023-06-28)


### Bug Fixes

* Allow url rewrites with only a subset of fields set (proxy mode) ([109365f](https://github.com/dadrus/heimdall/commit/109365f7f4fecabfd7ee5abb112f0338af23ce13))
* Include fullname in Helm RBAC resource names ([#737](https://github.com/dadrus/heimdall/issues/737)) ([dff3d4d](https://github.com/dadrus/heimdall/commit/dff3d4da3ef2baf46ee3064a88dd4984a7fdbb74))
* Working `authClassName` filter if multiple heimdall deployments are present in a cluster ([#742](https://github.com/dadrus/heimdall/issues/742)) ([109365f](https://github.com/dadrus/heimdall/commit/109365f7f4fecabfd7ee5abb112f0338af23ce13))

## [0.10.0-alpha](https://github.com/dadrus/heimdall/compare/v0.9.1-alpha...v0.10.0-alpha) (2023-06-28)


### ⚠ BREAKING CHANGES

* Support for URL rewriting while forwarding the processed request to the upstream service ([#703](https://github.com/dadrus/heimdall/issues/703))

### Features

* Support for automatically Helm roll deployments ([#731](https://github.com/dadrus/heimdall/issues/731)) ([bd2d438](https://github.com/dadrus/heimdall/commit/bd2d43815893aacb863aeaf5eec3f183fa71fde1))
* Support for URL rewriting while forwarding the processed request to the upstream service ([#703](https://github.com/dadrus/heimdall/issues/703)) ([be62972](https://github.com/dadrus/heimdall/commit/be62972b4cd07f96fce581ee16901dd2b586456a))

## [0.9.1-alpha](https://github.com/dadrus/heimdall/compare/v0.9.0-alpha...v0.9.1-alpha) (2023-06-24)


### Bug Fixes

* Matcher expressions do not have to cope with url encoded path fragments any more if such are present ([#721](https://github.com/dadrus/heimdall/issues/721)) ([4a8b0a0](https://github.com/dadrus/heimdall/commit/4a8b0a048fde6b306773ffee2dc8feb56610fa0a))
* Query parameters are now ignored while matching the request url ([#719](https://github.com/dadrus/heimdall/issues/719)) ([69fce94](https://github.com/dadrus/heimdall/commit/69fce9411fddafe5e043309ff1296d4b601373bc))
* URL encoding fixed while forwarding the request to the upstream in proxy mode ([#716](https://github.com/dadrus/heimdall/issues/716)) ([9234ea1](https://github.com/dadrus/heimdall/commit/9234ea168cf94b32e4a4d5e1486ec6552d9b7d37))

## [0.9.0-alpha](https://github.com/dadrus/heimdall/compare/v0.8.2-alpha...v0.9.0-alpha) (2023-06-23)


### Features

* Configuration for read and write buffer sizes ([#706](https://github.com/dadrus/heimdall/issues/706)) ([6dcab1f](https://github.com/dadrus/heimdall/commit/6dcab1ff43bccef86b97173ffb953891983ed3a6))
* Support for `X-Original-Method` used by nginx ingress controller ([#710](https://github.com/dadrus/heimdall/issues/710)) ([d95b989](https://github.com/dadrus/heimdall/commit/d95b989031f757d63349ce0536a6664b207aaf3a))


### Bug Fixes

* Refresh of cached items disabled to avoid retrieval of stale items ([#711](https://github.com/dadrus/heimdall/issues/711)) ([82c869b](https://github.com/dadrus/heimdall/commit/82c869b3f3dc2ab1d4d25d04029ccd928a6fadf4))

## [0.8.2-alpha](https://github.com/dadrus/heimdall/compare/v0.8.1-alpha...v0.8.2-alpha) (2023-06-21)


### Bug Fixes

* fix for panic on request handling if no rules are available ([#699](https://github.com/dadrus/heimdall/issues/699)) ([241f8ae](https://github.com/dadrus/heimdall/commit/241f8ae244b926d75514a43b5aa35d2d3a74281e))
* leading slash is not added to the URL path anymore during URL path extraction ([#695](https://github.com/dadrus/heimdall/issues/695)) ([33679a6](https://github.com/dadrus/heimdall/commit/33679a6a24b03a61d5bd62e040865301fee5a9a6))
* nginx controller workaround ([#691](https://github.com/dadrus/heimdall/issues/691)) ([427751d](https://github.com/dadrus/heimdall/commit/427751df312eee8d15b8b5f37e5947d8208dfc3d))

## [0.8.1-alpha](https://github.com/dadrus/heimdall/compare/v0.8.0-alpha...v0.8.1-alpha) (2023-06-12)


### Bug Fixes

* Proper usage of system trust store for JWT signer certificate validation purposes ([#671](https://github.com/dadrus/heimdall/issues/671)) ([66835b6](https://github.com/dadrus/heimdall/commit/66835b6acd6f2601fb53e48e36b4fe2c6b908989))

## [0.8.0-alpha](https://github.com/dadrus/heimdall/compare/v0.7.0-alpha...v0.8.0-alpha) (2023-06-07)


### ⚠ BREAKING CHANGES

* `generic` authenticator can forward authentication data to the `identity_info_endpoint` based on custom configuration ([#631](https://github.com/dadrus/heimdall/issues/631))

### Features

* `api_key` endpoint authentication strategy can add api keys to query parameters ([#630](https://github.com/dadrus/heimdall/issues/630)) ([634c9d9](https://github.com/dadrus/heimdall/commit/634c9d9f70cf24422023e1095d1f3c8f62290b05))
* `generic` authenticator can forward authentication data to the `identity_info_endpoint` based on custom configuration ([#631](https://github.com/dadrus/heimdall/issues/631)) ([0e26596](https://github.com/dadrus/heimdall/commit/0e26596e9c610c02139e6883bec867ee3c101714))
* `jwt` unifier supports definition of a custom header and scheme ([#666](https://github.com/dadrus/heimdall/issues/666)) ([9971faa](https://github.com/dadrus/heimdall/commit/9971faa5ae7ecdcdf61671946305fe41c7b518de))
* Request object is available to `header` and `cookie` unifiers ([#627](https://github.com/dadrus/heimdall/issues/627)) ([71b1da5](https://github.com/dadrus/heimdall/commit/71b1da5c24839cb1b45f2db1a8bdd45aff172f6c))


### Bug Fixes

* Proper HTTP hop by hop header handling ([#665](https://github.com/dadrus/heimdall/issues/665)) ([3ef6185](https://github.com/dadrus/heimdall/commit/3ef61858301a0d7dfd4efa2b81bd1be92b67efd3))


### Performance Improvements

* converting byte slice to a string and vice versa without memory allocation ([#649](https://github.com/dadrus/heimdall/issues/649)) ([6a13428](https://github.com/dadrus/heimdall/commit/6a134287c3d7debfdaa857d8c422a240e7f897e9))

## [0.7.0-alpha](https://github.com/dadrus/heimdall/compare/v0.6.1-alpha...v0.7.0-alpha) (2023-04-17)


### ⚠ BREAKING CHANGES

* Version schema for rule sets ([#436](https://github.com/dadrus/heimdall/issues/436))
* CORS support for decision service removed ([#487](https://github.com/dadrus/heimdall/issues/487))

### Features

* Command for validation of rules ([#557](https://github.com/dadrus/heimdall/issues/557)) ([849ed25](https://github.com/dadrus/heimdall/commit/849ed256642f57f856793f47ca22ab8afc34f2b6))
* Conditional execution of authorizers, contextualizers and unifiers in a rule ([#562](https://github.com/dadrus/heimdall/issues/562)) ([72db66e](https://github.com/dadrus/heimdall/commit/72db66e05246ad44916fa6d570996a178ed565da))
* Contextualizer can be configured not to cancel the pipeline execution if it runs into an error ([#522](https://github.com/dadrus/heimdall/issues/522)) ([ad0d956](https://github.com/dadrus/heimdall/commit/ad0d956474bbac4037da6674fb42a0f687236e1b))
* logging version information on start ([#555](https://github.com/dadrus/heimdall/issues/555)) ([92b6564](https://github.com/dadrus/heimdall/commit/92b65641a514df8adf3a348211e337d330d55b71))
* Rule controlled endpoint templating ([#572](https://github.com/dadrus/heimdall/issues/572)) ([41adfb9](https://github.com/dadrus/heimdall/commit/41adfb9155e74f96067c05c3488a126aa207fe9d))
* Support for envoy gRPC v3 external authorization API ([#469](https://github.com/dadrus/heimdall/issues/469)) ([666cd07](https://github.com/dadrus/heimdall/commit/666cd07453af7b7aa28d4c0c9ac383df516ef37f))
* Version schema for rule sets ([#436](https://github.com/dadrus/heimdall/issues/436)) ([dba0a87](https://github.com/dadrus/heimdall/commit/dba0a8793bc510407e616960896a3665b15d391d))


### Bug Fixes

* Configuration of `basic_auth` authenticator fixed ([#556](https://github.com/dadrus/heimdall/issues/556)) ([8eb5f65](https://github.com/dadrus/heimdall/commit/8eb5f653acbc9670a6cb09cdc7743ac48ce84751))
* Initialzation of `Subject.Attributes` by `anonymous` authenticator  ([#566](https://github.com/dadrus/heimdall/issues/566)) ([425acb8](https://github.com/dadrus/heimdall/commit/425acb8f2955a061e0782a09d631c97f859d98e4))


### Code Refactoring

* CORS support for decision service removed ([#487](https://github.com/dadrus/heimdall/issues/487)) ([1339721](https://github.com/dadrus/heimdall/commit/13397211a84b66bcae94dc8891c06c9c7deb1f31))

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
