# Changelog

## [0.15.9](https://github.com/dadrus/heimdall/compare/v0.15.8...v0.15.9) (2025-03-06)


### Bug Fixes

* Resolved panic triggered by using an empty string as a template value ([#2274](https://github.com/dadrus/heimdall/issues/2274)) ([7b8eacc](https://github.com/dadrus/heimdall/commit/7b8eacc02648e64237ce0c33af3c70e9bd1034de))


### Dependencies

* update golang to v1.24.1 ([#2266](https://github.com/dadrus/heimdall/issues/2266)) ([0b1b1b3](https://github.com/dadrus/heimdall/commit/0b1b1b3abd8911bb84b38f29233d793863c6f30d))
* update golang.org/x/exp digest to 054e65f ([#2270](https://github.com/dadrus/heimdall/issues/2270)) ([f3ad941](https://github.com/dadrus/heimdall/commit/f3ad94157da67fe4971c11ea88b3f7257797ec41))
* update google.golang.org/genproto/googleapis/rpc digest to a0af3ef ([#2258](https://github.com/dadrus/heimdall/issues/2258)) ([bb7f477](https://github.com/dadrus/heimdall/commit/bb7f477b493b7cac7974575d43d59b57d8e8f31b))
* update module github.com/grpc-ecosystem/go-grpc-middleware/v2 to v2.3.1 ([#2271](https://github.com/dadrus/heimdall/issues/2271)) ([0700616](https://github.com/dadrus/heimdall/commit/07006167c46bbb0bf2d96974113d2201ebdcac64))
* update module github.com/prometheus/client_golang to v1.21.1 ([#2262](https://github.com/dadrus/heimdall/issues/2262)) ([2dd0df4](https://github.com/dadrus/heimdall/commit/2dd0df46cb973b42fbb589e7851ec2822bb78464))
* update module golang.org/x/oauth2 to 0.28.0 ([#2275](https://github.com/dadrus/heimdall/issues/2275)) ([df6f5bf](https://github.com/dadrus/heimdall/commit/df6f5bfd95238dedc1b85c5068a3a6cfa1ad8954))
* update module google.golang.org/grpc to v1.71.0 ([#2263](https://github.com/dadrus/heimdall/issues/2263)) ([b4fca46](https://github.com/dadrus/heimdall/commit/b4fca4663a5184cb7aac4727dbba07fa6e092a40))
* update opentelemetry-go monorepo to v1.35.0 ([#2269](https://github.com/dadrus/heimdall/issues/2269)) ([37c550f](https://github.com/dadrus/heimdall/commit/37c550ff83d204266d39d3e70c42fb528784c7bc))

## [0.15.8](https://github.com/dadrus/heimdall/compare/v0.15.7...v0.15.8) (2025-03-03)


### Bug Fixes

* `X-Forwarded-For`, `-Proto`, `-Host` and `Forwarded` are always send to the upstream in proxy mode ([#2250](https://github.com/dadrus/heimdall/issues/2250)) ([41ff9fa](https://github.com/dadrus/heimdall/commit/41ff9fa55c32673da2d297d48340fdcbc5d1b946))
* IPv6 address is properly encoded in the `for` directive of the `Forwarded` header ([#2250](https://github.com/dadrus/heimdall/issues/2250)) ([41ff9fa](https://github.com/dadrus/heimdall/commit/41ff9fa55c32673da2d297d48340fdcbc5d1b946))
* Matching multiple hosts implements OR logic now ([#2234](https://github.com/dadrus/heimdall/issues/2234)) ([521baf4](https://github.com/dadrus/heimdall/commit/521baf413727e3f375eb05869f299379bebb84e8))
* Multiple header with same name but different values ([#2242](https://github.com/dadrus/heimdall/issues/2242)) ([2c749b4](https://github.com/dadrus/heimdall/commit/2c749b447d21e7b15cb866f3a3478eddd44feda5))


### Dependencies

* update golang.org/x/exp digest to dead583 ([#2249](https://github.com/dadrus/heimdall/issues/2249)) ([664a117](https://github.com/dadrus/heimdall/commit/664a117f38efba0673559f061d2d91b9669995db))
* update google.golang.org/genproto/googleapis/rpc digest to 55c9018 ([#2247](https://github.com/dadrus/heimdall/issues/2247)) ([ab1fa42](https://github.com/dadrus/heimdall/commit/ab1fa425260e0d355ceb3a8e541626b70a100270))
* update module github.com/google/cel-go to v0.24.1 ([#2240](https://github.com/dadrus/heimdall/issues/2240)) ([9aa4632](https://github.com/dadrus/heimdall/commit/9aa4632fbf316a79fa48b987ca6ccc52701d20a1))

## [0.15.7](https://github.com/dadrus/heimdall/compare/v0.15.6...v0.15.7) (2025-02-25)


### Bug Fixes

* `oauth2_introspection` authenticator does not require issuer assertion configuration ([#2219](https://github.com/dadrus/heimdall/issues/2219)) ([6d95700](https://github.com/dadrus/heimdall/commit/6d957002d3136066ff67ab51ffdea114f01d615b))
* `www_authenticate` error handler schema typo ([#2201](https://github.com/dadrus/heimdall/issues/2201)) ([67be2d0](https://github.com/dadrus/heimdall/commit/67be2d0076b41ad25207e89b74383a1a850e2f06))


### Dependencies

* update golang.org/x/exp digest to aa4b98e ([#2194](https://github.com/dadrus/heimdall/issues/2194)) ([ec315dc](https://github.com/dadrus/heimdall/commit/ec315dc9357cee50298a32ad53dc3451091c60c6))
* update google.golang.org/genproto/googleapis/rpc digest to 546df14 ([#2213](https://github.com/dadrus/heimdall/issues/2213)) ([e7a98b1](https://github.com/dadrus/heimdall/commit/e7a98b12c40198065a115827fc246fdd7d01e1bf))
* update module github.com/go-co-op/gocron/v2 to v2.16.0 ([#2216](https://github.com/dadrus/heimdall/issues/2216)) ([a22a6f1](https://github.com/dadrus/heimdall/commit/a22a6f16b7d44231c82fe3be28bdb2dc6970b91f))
* update module github.com/go-jose/go-jose/v4 to v4.0.5 [security] ([#2214](https://github.com/dadrus/heimdall/issues/2214)) ([ae3d680](https://github.com/dadrus/heimdall/commit/ae3d68021739d8bb26e3d0d49283517b1c8480bb))
* update module github.com/grpc-ecosystem/go-grpc-middleware/v2 to v2.3.0 ([#2192](https://github.com/dadrus/heimdall/issues/2192)) ([d4c2d83](https://github.com/dadrus/heimdall/commit/d4c2d8387b0bcbd024db8293de8a19ca8508be7d))
* update module github.com/prometheus/client_golang to v1.21.0 ([#2197](https://github.com/dadrus/heimdall/issues/2197)) ([221cccc](https://github.com/dadrus/heimdall/commit/221cccc05dd4e6f9b05647bae6818861e13cc751))
* update module github.com/redis/rueidis to v1.0.55 ([#2210](https://github.com/dadrus/heimdall/issues/2210)) ([df2291f](https://github.com/dadrus/heimdall/commit/df2291f47a0dfbc3667561b6a8ca2546f7539422))
* update module github.com/redis/rueidis/rueidisotel to v1.0.55 ([#2211](https://github.com/dadrus/heimdall/issues/2211)) ([953722c](https://github.com/dadrus/heimdall/commit/953722c02019f446bca0b88230949a1b146ea579))
* update module github.com/spf13/cobra to v1.9.1 ([#2188](https://github.com/dadrus/heimdall/issues/2188)) ([c0590d6](https://github.com/dadrus/heimdall/commit/c0590d6c66a405f72a895606365ff1287d869491))

## [0.15.6](https://github.com/dadrus/heimdall/compare/v0.15.5...v0.15.6) (2025-02-16)


### Bug Fixes

* HTTPS scheme configured for the probes if the management service is configured with TLS ([#2176](https://github.com/dadrus/heimdall/issues/2176)) ([8eacfb2](https://github.com/dadrus/heimdall/commit/8eacfb2156f0fbde227bb179b086add7ac079f03))


### Dependencies

* update github.com/dadrus/httpsig digest to 523cd6a ([#2182](https://github.com/dadrus/heimdall/issues/2182)) ([6608472](https://github.com/dadrus/heimdall/commit/6608472ead9bc80b92c320faacb87c5d2ba42ff6))
* update golang to v1.24.0 ([#2170](https://github.com/dadrus/heimdall/issues/2170)) ([2de5e01](https://github.com/dadrus/heimdall/commit/2de5e015ca1a056e453f4025c357e06b3f78104b))
* update golang.org/x/exp digest to eff6e97 ([#2179](https://github.com/dadrus/heimdall/issues/2179)) ([c2046ed](https://github.com/dadrus/heimdall/commit/c2046ed64f3625893580895abfbc3b70bad1451c))
* update google.golang.org/genproto/googleapis/rpc digest to 5a70512 ([#2169](https://github.com/dadrus/heimdall/issues/2169)) ([1b82319](https://github.com/dadrus/heimdall/commit/1b82319f5b0d478a1bf2895a861fcf7af0ce62e9))
* update kubernetes packages to v0.32.2 ([#2172](https://github.com/dadrus/heimdall/issues/2172)) ([85dbb2a](https://github.com/dadrus/heimdall/commit/85dbb2a4639c019e8284728f792aea7fb2ab2dbd))
* update module github.com/dlclark/regexp2 to v1.11.5 ([#2163](https://github.com/dadrus/heimdall/issues/2163)) ([02005af](https://github.com/dadrus/heimdall/commit/02005af533dc86b2a5ae8cfba7501e194a3ca82c))
* update module github.com/envoyproxy/go-control-plane/envoy to v1.32.4 ([#2147](https://github.com/dadrus/heimdall/issues/2147)) ([5bdddee](https://github.com/dadrus/heimdall/commit/5bdddeebb6bf9cd92b8bbf3e8f1c44a50bb132de))
* update module github.com/evanphx/json-patch/v5 to v5.9.11 ([#2144](https://github.com/dadrus/heimdall/issues/2144)) ([ce30a8d](https://github.com/dadrus/heimdall/commit/ce30a8d0ee82d37797932b6b8efca97ba22470bf))
* update module github.com/go-co-op/gocron/v2 to v2.15.0 ([#2134](https://github.com/dadrus/heimdall/issues/2134)) ([6f38b20](https://github.com/dadrus/heimdall/commit/6f38b203217167b0864e7b3e6a455dd2b38163a3))
* update module github.com/go-playground/validator/v10 to v10.25.0 ([#2178](https://github.com/dadrus/heimdall/issues/2178)) ([ba12308](https://github.com/dadrus/heimdall/commit/ba1230859320cb2c955a3c65c7feff0c6431b1b7))
* update module github.com/goccy/go-json to v0.10.5 ([#2142](https://github.com/dadrus/heimdall/issues/2142)) ([bee7233](https://github.com/dadrus/heimdall/commit/bee72330d0ee5fe20bcd2bafe9dddb21eaaf3c04))
* update module github.com/google/cel-go to v0.23.2 ([#2145](https://github.com/dadrus/heimdall/issues/2145)) ([807fa38](https://github.com/dadrus/heimdall/commit/807fa38bf6f6d5fe36401dd2f2d8be166b89c78d))
* update module github.com/redis/rueidis to v1.0.54 ([#2148](https://github.com/dadrus/heimdall/issues/2148)) ([53eb595](https://github.com/dadrus/heimdall/commit/53eb5954a534803e8b08f13be72fa648d1146185))
* update module github.com/redis/rueidis/rueidisotel to v1.0.54 ([#2149](https://github.com/dadrus/heimdall/issues/2149)) ([0eec13c](https://github.com/dadrus/heimdall/commit/0eec13c4110326d7002d86b6959e55e2c6d01a1f))
* update module github.com/spf13/cobra to v1.9.0 ([#2180](https://github.com/dadrus/heimdall/issues/2180)) ([103bb9a](https://github.com/dadrus/heimdall/commit/103bb9a81949b89cb307260080e23cbef2d11550))
* update module google.golang.org/grpc to v1.70.0 ([#2127](https://github.com/dadrus/heimdall/issues/2127)) ([4eb855c](https://github.com/dadrus/heimdall/commit/4eb855c6e285bbb5904c482cca0ee5a69e34b102))
* update module google.golang.org/protobuf to v1.36.5 ([#2157](https://github.com/dadrus/heimdall/issues/2157)) ([812263a](https://github.com/dadrus/heimdall/commit/812263a194fae71167fb56c54bad3b6a304d6689))
* update module k8s.io/client-go to v0.32.2 ([#2173](https://github.com/dadrus/heimdall/issues/2173)) ([80d7687](https://github.com/dadrus/heimdall/commit/80d7687a347f410ad6c5bc25db3fe756a98b8a72))

## [0.15.5](https://github.com/dadrus/heimdall/compare/v0.15.4...v0.15.5) (2025-01-20)


### Dependencies

* update github.com/dadrus/httpsig digest to 6cb9b82 ([#2108](https://github.com/dadrus/heimdall/issues/2108)) ([23dfb03](https://github.com/dadrus/heimdall/commit/23dfb032ccb98ed9cac7a9ba705abd42725e74fe))
* update golang to v1.23.5 ([#2109](https://github.com/dadrus/heimdall/issues/2109)) ([af4eee7](https://github.com/dadrus/heimdall/commit/af4eee721d301b29986831f8691a13233f513526))
* update google.golang.org/genproto/googleapis/rpc digest to 1a7da9e ([#2105](https://github.com/dadrus/heimdall/issues/2105)) ([e2a1698](https://github.com/dadrus/heimdall/commit/e2a1698242a61dd10bb41ee938ca27312e0d0e57))
* update kubernetes packages to v0.32.1 ([#2107](https://github.com/dadrus/heimdall/issues/2107)) ([266fa95](https://github.com/dadrus/heimdall/commit/266fa95b6c6dda78e3fd99ce4e00164e077e95ec))
* update module github.com/envoyproxy/go-control-plane to v0.13.4 ([#2080](https://github.com/dadrus/heimdall/issues/2080)) ([ca83050](https://github.com/dadrus/heimdall/commit/ca83050b80ba0495042e25b425d648910c4fddab))
* update module github.com/go-co-op/gocron/v2 to v2.14.2 ([#2085](https://github.com/dadrus/heimdall/issues/2085)) ([9ab4019](https://github.com/dadrus/heimdall/commit/9ab4019e33eefc68f7912bfc981513818c270d52))
* update module github.com/go-playground/validator/v10 to v10.24.0 ([#2097](https://github.com/dadrus/heimdall/issues/2097)) ([52620e5](https://github.com/dadrus/heimdall/commit/52620e52b63aafc9115ad96df16fc280b83ccf0a))
* update module github.com/redis/rueidis to v1.0.53 ([#2099](https://github.com/dadrus/heimdall/issues/2099)) ([d8187ee](https://github.com/dadrus/heimdall/commit/d8187eeadf5944b85d340e6624df9515d4852e08))
* update module github.com/redis/rueidis/rueidisotel to v1.0.53 ([#2100](https://github.com/dadrus/heimdall/issues/2100)) ([b472480](https://github.com/dadrus/heimdall/commit/b472480789e8c85c3bbafea0f8e019fc50a4a8fb))
* update module google.golang.org/grpc to v1.69.4 ([#2098](https://github.com/dadrus/heimdall/issues/2098)) ([f0b67d8](https://github.com/dadrus/heimdall/commit/f0b67d80cf0345cdbfd241a511fec18962b580e3))
* update module google.golang.org/protobuf to v1.36.3 ([#2103](https://github.com/dadrus/heimdall/issues/2103)) ([a67f183](https://github.com/dadrus/heimdall/commit/a67f1832f4a0117944a2dd5e8688a1ec61f574d2))
* update opentelemetry-go monorepo v1.34.0 ([#2111](https://github.com/dadrus/heimdall/issues/2111)) ([28e3249](https://github.com/dadrus/heimdall/commit/28e3249ccf4b2ce0985515885bfcf5021ee86f17))
* update opentelemetry-go-contrib monorepo to v0.59.0 ([#2112](https://github.com/dadrus/heimdall/issues/2112)) ([9ec1e1f](https://github.com/dadrus/heimdall/commit/9ec1e1f6e2c560766d9c0d25c2b15c24402b1223))

## [0.15.4](https://github.com/dadrus/heimdall/compare/v0.15.3...v0.15.4) (2024-12-19)


### Bug Fixes

* Correlation of OTEL Traces and Logs ([#2049](https://github.com/dadrus/heimdall/issues/2049)) ([69c657c](https://github.com/dadrus/heimdall/commit/69c657cda83f8379775d8b9ef82927d9fff15d71))


### Dependencies

* update golang.org/x/exp digest to b2144cd ([#2041](https://github.com/dadrus/heimdall/issues/2041)) ([40deb32](https://github.com/dadrus/heimdall/commit/40deb328769d3d06e282a74d8a0037b8ae6d3806))
* update google.golang.org/genproto/googleapis/rpc digest to 9240e9c ([#2037](https://github.com/dadrus/heimdall/issues/2037)) ([0f5d17c](https://github.com/dadrus/heimdall/commit/0f5d17c5da9dec9b8753a8131b5fafa65d620716))
* update module github.com/go-co-op/gocron/v2 to v2.14.0 ([#2043](https://github.com/dadrus/heimdall/issues/2043)) ([dbe861c](https://github.com/dadrus/heimdall/commit/dbe861cd07d345a7eba29a83b43c7ee324d94a26))
* update module golang.org/x/net to v0.33.0 ([#2052](https://github.com/dadrus/heimdall/issues/2052)) ([7d28110](https://github.com/dadrus/heimdall/commit/7d281109f0ea18ac1eb38795d80f4b4fd5088f4e))
* update module google.golang.org/grpc to v1.69.2 ([#2046](https://github.com/dadrus/heimdall/issues/2046)) ([2a639c0](https://github.com/dadrus/heimdall/commit/2a639c04d50b700611926666a69ed9c585bb9de9))
* update module google.golang.org/protobuf to v1.36.0 ([#2038](https://github.com/dadrus/heimdall/issues/2038)) ([55eb060](https://github.com/dadrus/heimdall/commit/55eb060545f1f61bfead8c3f28456ec96683efc6))

## [0.15.3](https://github.com/dadrus/heimdall/compare/v0.15.2...v0.15.3) (2024-12-15)


### Dependencies

* update github.com/dadrus/httpsig digest to ede02f5 ([#2028](https://github.com/dadrus/heimdall/issues/2028)) ([2e7c22b](https://github.com/dadrus/heimdall/commit/2e7c22b5f2d92e0ecdf319b1bfb909b6b3f89d28))
* update golang to v1.23.4 ([#1999](https://github.com/dadrus/heimdall/issues/1999)) ([84a7cd2](https://github.com/dadrus/heimdall/commit/84a7cd207e963e4852f9218ed01fbaa7958c09f2))
* update golang.org/x/exp digest to 1829a12 ([#2009](https://github.com/dadrus/heimdall/issues/2009)) ([7a3eedd](https://github.com/dadrus/heimdall/commit/7a3eedd683420fd333b37c16a96cc7c914598741))
* update google.golang.org/genproto/googleapis/rpc digest to e6fa225 ([#2007](https://github.com/dadrus/heimdall/issues/2007)) ([c48cdd6](https://github.com/dadrus/heimdall/commit/c48cdd69eca8ac5b8254c32beb47739df3a9992d))
* update kubernetes packages to v0.32.0 ([#2014](https://github.com/dadrus/heimdall/issues/2014)) ([1af65e1](https://github.com/dadrus/heimdall/commit/1af65e18385240518d28d690c03bfa786b04d136))
* update module github.com/go-co-op/gocron/v2 to v2.13.0 ([#2017](https://github.com/dadrus/heimdall/issues/2017)) ([c6c522c](https://github.com/dadrus/heimdall/commit/c6c522cdd1efc18092f3318c3572521fb01e042f))
* update module github.com/go-playground/validator/v10 to v10.23.0 ([#1973](https://github.com/dadrus/heimdall/issues/1973)) ([8760824](https://github.com/dadrus/heimdall/commit/8760824bbd482f50742c54d25177ab93285dc9fb))
* update module github.com/goccy/go-json to v0.10.4 ([#2016](https://github.com/dadrus/heimdall/issues/2016)) ([684be26](https://github.com/dadrus/heimdall/commit/684be261e9c4bea1f62550582819dcfbd25679e3))
* update module github.com/google/cel-go to v0.22.1 ([#1986](https://github.com/dadrus/heimdall/issues/1986)) ([09404f8](https://github.com/dadrus/heimdall/commit/09404f8b2cee44793cffabf259df6f34ea1abae0))
* update module github.com/grpc-ecosystem/go-grpc-middleware/v2 to v2.2.0 ([#2013](https://github.com/dadrus/heimdall/issues/2013)) ([1f580bc](https://github.com/dadrus/heimdall/commit/1f580bcb0ac76b9de2642ccf1f1279c0fdb1200e))
* update module github.com/redis/rueidis to v1.0.51 ([#1993](https://github.com/dadrus/heimdall/issues/1993)) ([c407e5f](https://github.com/dadrus/heimdall/commit/c407e5f067aa90a41ba1a46a618d24dc23db1ca5))
* update module github.com/redis/rueidis/rueidisotel to v1.0.51 ([#1994](https://github.com/dadrus/heimdall/issues/1994)) ([b800657](https://github.com/dadrus/heimdall/commit/b8006578b3e1da1fab010e8623d379f1f0304f7a))
* update module github.com/wi2l/jsondiff to v0.6.1 ([#1974](https://github.com/dadrus/heimdall/issues/1974)) ([f488ebe](https://github.com/dadrus/heimdall/commit/f488ebef693344abfd2982bd012daabfb755e908))
* update module go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc to v0.58.0 ([#2021](https://github.com/dadrus/heimdall/issues/2021)) ([67dd34e](https://github.com/dadrus/heimdall/commit/67dd34e5f7201ff20b3c01f61761c0a33831a866))
* update module go.opentelemetry.io/contrib/instrumentation/host to v0.58.0 ([#2022](https://github.com/dadrus/heimdall/issues/2022)) ([ba66098](https://github.com/dadrus/heimdall/commit/ba660988bf91072225918944bafd5c9f518583d6))
* update module go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp to v0.58.0 ([#2023](https://github.com/dadrus/heimdall/issues/2023)) ([83efbbf](https://github.com/dadrus/heimdall/commit/83efbbf01a0b914b20200d6d1fca4d8f2c1e4541))
* update module go.opentelemetry.io/contrib/instrumentation/runtime to v0.58.0 ([#2025](https://github.com/dadrus/heimdall/issues/2025)) ([6c32af0](https://github.com/dadrus/heimdall/commit/6c32af0bad77a261145921a055268227899ef939))
* update module go.opentelemetry.io/contrib/propagators/autoprop to v0.58.0 ([#2026](https://github.com/dadrus/heimdall/issues/2026)) ([eb53f4c](https://github.com/dadrus/heimdall/commit/eb53f4c1038f6122322300509deaf7652f3458be))
* update module google.golang.org/grpc to v1.69.0 ([#2018](https://github.com/dadrus/heimdall/issues/2018)) ([11b1beb](https://github.com/dadrus/heimdall/commit/11b1bebac180f4557b52072bed33cdba12ffc382))
* update module google.golang.org/protobuf to v1.35.2 ([#1968](https://github.com/dadrus/heimdall/issues/1968)) ([10e34e7](https://github.com/dadrus/heimdall/commit/10e34e7ac024a0bc3c931374a629581657b219ce))
* update opentelemetry-go monorepo to v1.33.0 ([#2019](https://github.com/dadrus/heimdall/issues/2019)) ([2192811](https://github.com/dadrus/heimdall/commit/2192811b56088c9b2e4af1362da4bbc118b83b63))

## [0.15.2](https://github.com/dadrus/heimdall/compare/v0.15.1...v0.15.2) (2024-11-10)


### Dependencies

* update github.com/dadrus/httpsig digest to e11d675 ([#1936](https://github.com/dadrus/heimdall/issues/1936)) ([926aaa2](https://github.com/dadrus/heimdall/commit/926aaa2a8fdec5f8771a3e0e421b2590a979c1b4))
* update golang to v1.23.3 ([#1943](https://github.com/dadrus/heimdall/issues/1943)) ([821606b](https://github.com/dadrus/heimdall/commit/821606b49a5d5f023eaad053d3031fd847c717b9))
* update golang.org/x/exp digest to 2d47ceb ([#1949](https://github.com/dadrus/heimdall/issues/1949)) ([d677013](https://github.com/dadrus/heimdall/commit/d677013020163014b2c7d8c82ffd5f201b9e7c3b))
* update google.golang.org/genproto/googleapis/rpc digest to dd2ea8e ([#1938](https://github.com/dadrus/heimdall/issues/1938)) ([01a6c75](https://github.com/dadrus/heimdall/commit/01a6c753296dc4726a36d4655eba5bab0c251fb7))
* update kubernetes packages to v0.31.2 ([#1921](https://github.com/dadrus/heimdall/issues/1921)) ([21919a9](https://github.com/dadrus/heimdall/commit/21919a921e42bb065bfd64b46c9ae4ea51754c3d))
* update module github.com/envoyproxy/go-control-plane to v0.13.1 ([#1904](https://github.com/dadrus/heimdall/issues/1904)) ([dcb88fb](https://github.com/dadrus/heimdall/commit/dcb88fbf9ce6db1eef2ff8eeae3dfdbfd3588aaf))
* update module github.com/fsnotify/fsnotify to v1.8.0 ([#1932](https://github.com/dadrus/heimdall/issues/1932)) ([b8a8c05](https://github.com/dadrus/heimdall/commit/b8a8c0581d062b462374b1882d158de3d7c9ea8c))
* update module github.com/go-co-op/gocron/v2 to v2.12.3 ([#1933](https://github.com/dadrus/heimdall/issues/1933)) ([0a9185b](https://github.com/dadrus/heimdall/commit/0a9185b6cd293743be146ac602e424d3096ce75e))
* update module github.com/google/cel-go to v0.22.0 ([#1942](https://github.com/dadrus/heimdall/issues/1942)) ([0583e0e](https://github.com/dadrus/heimdall/commit/0583e0e997276655c0591ceca5f8426ff25f8947))
* update module github.com/knadh/koanf/v2 to v2.1.2 ([#1940](https://github.com/dadrus/heimdall/issues/1940)) ([cc31181](https://github.com/dadrus/heimdall/commit/cc311816ef48e2bc483668680ee29d0a5e9f571f))
* update module github.com/redis/rueidis to v1.0.49 ([#1947](https://github.com/dadrus/heimdall/issues/1947)) ([19d38cf](https://github.com/dadrus/heimdall/commit/19d38cfed49be52cc09e27318333b19c7ec04cd3))
* update module github.com/redis/rueidis/rueidisotel to v1.0.49 ([#1947](https://github.com/dadrus/heimdall/issues/1947)) ([19d38cf](https://github.com/dadrus/heimdall/commit/19d38cfed49be52cc09e27318333b19c7ec04cd3))
* update module go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc to v0.57.0 ([#1950](https://github.com/dadrus/heimdall/issues/1950)) ([798b2fe](https://github.com/dadrus/heimdall/commit/798b2fe8dd82b502edee139778d67461c26b7d6d))
* update module go.opentelemetry.io/contrib/instrumentation/host to v0.57.0 ([#1951](https://github.com/dadrus/heimdall/issues/1951)) ([ea21fb0](https://github.com/dadrus/heimdall/commit/ea21fb09098b7ba4b5fe8bbbd1ce64524facadde))
* update module go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp to v0.57.0 ([#1952](https://github.com/dadrus/heimdall/issues/1952)) ([435cfdb](https://github.com/dadrus/heimdall/commit/435cfdb0cbab3d7d2a5d1bb6de3a3a9e40177096))
* update module go.opentelemetry.io/contrib/instrumentation/runtime to v0.57.0 ([#1953](https://github.com/dadrus/heimdall/issues/1953)) ([3a4fdf1](https://github.com/dadrus/heimdall/commit/3a4fdf1dac73c927190b9e7b13659b7023c17f4c))
* update module go.opentelemetry.io/contrib/propagators/autoprop to v0.57.0 ([#1954](https://github.com/dadrus/heimdall/issues/1954)) ([e1659c6](https://github.com/dadrus/heimdall/commit/e1659c6273545c81657edd9b732061dc1a50611e))
* update module google.golang.org/grpc to v1.68.0 ([#1945](https://github.com/dadrus/heimdall/issues/1945)) ([c0d5d9a](https://github.com/dadrus/heimdall/commit/c0d5d9aea66ba4f7f0e303c2fe49761b3ecc7146))
* update opentelemetry-go monorepo to v1.32.0 ([#1948](https://github.com/dadrus/heimdall/issues/1948)) ([6e42038](https://github.com/dadrus/heimdall/commit/6e4203820741e91f2c5d568e5073b79e1f647b50))

## [0.15.1](https://github.com/dadrus/heimdall/compare/v0.15.0...v0.15.1) (2024-10-16)


### Bug Fixes

* Certificate validation error in JWT finalizer for CA-issued certificates resolved ([#1900](https://github.com/dadrus/heimdall/issues/1900)) ([56eefa6](https://github.com/dadrus/heimdall/commit/56eefa6da2bb39dbfa8412a54a43ba36c8e2fd63))


### Dependencies

* update github.com/dadrus/httpsig digest to ae64249 ([#1895](https://github.com/dadrus/heimdall/issues/1895)) ([8d2f45c](https://github.com/dadrus/heimdall/commit/8d2f45c50df4a18a28ec0fae5592fec87f5b3865))
* update golang to v1.23.2 ([#1855](https://github.com/dadrus/heimdall/issues/1855)) ([4726671](https://github.com/dadrus/heimdall/commit/4726671d9601be12eb802bc880c43492e7a629f9))
* update golang.org/x/exp digest to f66d83c ([#1877](https://github.com/dadrus/heimdall/issues/1877)) ([32580a3](https://github.com/dadrus/heimdall/commit/32580a3b80240cf42733b31408cc3eb4a5b4d770))
* update google.golang.org/genproto/googleapis/rpc digest to 796eee8 ([#1893](https://github.com/dadrus/heimdall/issues/1893)) ([e7af4b4](https://github.com/dadrus/heimdall/commit/e7af4b4ec3b1e42ac0ce504dea99fc6b2d017892))
* update module github.com/go-co-op/gocron/v2 to v2.12.1 ([#1824](https://github.com/dadrus/heimdall/issues/1824)) ([6b76f53](https://github.com/dadrus/heimdall/commit/6b76f532b6cef8d1cef4af88d87fbc494cd32d70))
* update module github.com/go-viper/mapstructure/v2 to v2.2.1 ([#1826](https://github.com/dadrus/heimdall/issues/1826)) ([9202320](https://github.com/dadrus/heimdall/commit/92023200a228c7b6fd7e1377ece2acc18957fa7e))
* update module github.com/knadh/koanf/providers/env to v1 ([#1834](https://github.com/dadrus/heimdall/issues/1834)) ([33f0eb3](https://github.com/dadrus/heimdall/commit/33f0eb30e6e0a4729e7ad7150dabdf3039e674a6))
* update module github.com/prometheus/client_golang to v1.20.5 ([#1891](https://github.com/dadrus/heimdall/issues/1891)) ([9e65501](https://github.com/dadrus/heimdall/commit/9e65501caa4f2669963da49665add566e1992411))
* update module github.com/redis/rueidis to v1.0.47 ([#1850](https://github.com/dadrus/heimdall/issues/1850)) ([e2f355c](https://github.com/dadrus/heimdall/commit/e2f355cb245992668a800e0e98b7d94a38dcd9a2))
* update module github.com/redis/rueidis/rueidisotel to v1.0.47 ([#1851](https://github.com/dadrus/heimdall/issues/1851)) ([05c1fcd](https://github.com/dadrus/heimdall/commit/05c1fcde576f45362da7a6c703c9070d26f6e074))
* update module github.com/tidwall/gjson to v1.18.0 ([#1856](https://github.com/dadrus/heimdall/issues/1856)) ([9c75554](https://github.com/dadrus/heimdall/commit/9c755546e00917f08b5dddd76747e76d930b9fe6))
* update module go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc to v0.56.0 ([#1886](https://github.com/dadrus/heimdall/issues/1886)) ([f7ef870](https://github.com/dadrus/heimdall/commit/f7ef870f5e4d280a5a4ca089cf31b3b032815765))
* update module go.opentelemetry.io/contrib/instrumentation/host to v0.56.0 ([#1887](https://github.com/dadrus/heimdall/issues/1887)) ([d332b7a](https://github.com/dadrus/heimdall/commit/d332b7a933a034c7a129d444060dbadccc5ab04a))
* update module go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp to v0.56.0 ([#1888](https://github.com/dadrus/heimdall/issues/1888)) ([d28b36d](https://github.com/dadrus/heimdall/commit/d28b36d0434d87d4dd7f495a892ddea15d0c8288))
* update module go.opentelemetry.io/contrib/instrumentation/runtime to v0.56.0 ([#1889](https://github.com/dadrus/heimdall/issues/1889)) ([af86443](https://github.com/dadrus/heimdall/commit/af86443c3b83ec9a04bf71a7af578953a769b957))
* update module go.opentelemetry.io/contrib/propagators/autoprop to v0.56.0 ([#1890](https://github.com/dadrus/heimdall/issues/1890)) ([3928568](https://github.com/dadrus/heimdall/commit/39285685cb9b689c47dfe7cea970016361151c3e))
* update module go.uber.org/fx to v1.23.0 ([#1883](https://github.com/dadrus/heimdall/issues/1883)) ([b5a728c](https://github.com/dadrus/heimdall/commit/b5a728cf64a8ebbc1fb32b722315911b843492c3))
* update module gocloud.dev to v0.40.0 ([#1881](https://github.com/dadrus/heimdall/issues/1881)) ([6c1aef7](https://github.com/dadrus/heimdall/commit/6c1aef7fb1381348a83de188a17ada1bc26af86f))
* update module google.golang.org/grpc to v1.67.1 ([#1852](https://github.com/dadrus/heimdall/issues/1852)) ([e6314aa](https://github.com/dadrus/heimdall/commit/e6314aabbf6aa12e9c694e54227111f828bca844))
* update module google.golang.org/protobuf to v1.35.1 ([#1866](https://github.com/dadrus/heimdall/issues/1866)) ([6c39d92](https://github.com/dadrus/heimdall/commit/6c39d92d1f91b35ac684d770f7ce068ed08fde70))
* update opentelemetry-go monorepo to v1.31.0 ([#1884](https://github.com/dadrus/heimdall/issues/1884)) ([0730f13](https://github.com/dadrus/heimdall/commit/0730f1351cccf6e0d9c445f408527e86c1abec26))

## [0.15.0](https://github.com/dadrus/heimdall/compare/v0.14.0-alpha...v0.15.0) (2024-09-16)


### ⚠ BREAKING CHANGES

* Made the usage of `if` clauses in authentication & authorization, and error pipelines consistent ([#1784](https://github.com/dadrus/heimdall/issues/1784))
* Deprecated OTEL attributes replaced ([#1669](https://github.com/dadrus/heimdall/issues/1669))
* Configuration of `signer` moved into `jwt` finalizer ([#1534](https://github.com/dadrus/heimdall/issues/1534))
* Demo installation removed from the helm chart ([#1544](https://github.com/dadrus/heimdall/issues/1544))
* Subject has been made immutable ([#1487](https://github.com/dadrus/heimdall/issues/1487))
* Rule matching configuration API redesigned ([#1358](https://github.com/dadrus/heimdall/issues/1358))
* Default rule rejects requests with encoded slashes in the path of the URL with `400 Bad Request` ([#1358](https://github.com/dadrus/heimdall/issues/1358))
* Support for `rule_path_match_prefix` on endpoint configurations for `http_endpoint` and `cloud_blob` providers has been dropped ([#1358](https://github.com/dadrus/heimdall/issues/1358))

### Features

* Glob expressions are context aware and use `.` for host related expressions and `/` for path related ones as separators ([#1358](https://github.com/dadrus/heimdall/issues/1358)) ([f2f6867](https://github.com/dadrus/heimdall/commit/f2f6867576b758312b1a85dc06fe52be3ae9d2ff))
* Multiple rules can be defined for the same path, e.g. to have separate rules for read and write requests ([#1358](https://github.com/dadrus/heimdall/issues/1358)) ([f2f6867](https://github.com/dadrus/heimdall/commit/f2f6867576b758312b1a85dc06fe52be3ae9d2ff))
* New endpoint auth type to create http message signatures for outbound requests according to RFC 9421 ([#1507](https://github.com/dadrus/heimdall/issues/1507)) ([672988d](https://github.com/dadrus/heimdall/commit/672988d2463ddf8abbade7cb9f0656d848682ae3))
* Route based matching of rules ([#1766](https://github.com/dadrus/heimdall/issues/1766)) ([8ef379d](https://github.com/dadrus/heimdall/commit/8ef379db1d504440b6fa19794b7b38c173a730b0))
* Support for backtracking while matching rules ([#1358](https://github.com/dadrus/heimdall/issues/1358)) ([f2f6867](https://github.com/dadrus/heimdall/commit/f2f6867576b758312b1a85dc06fe52be3ae9d2ff))
* Support for free and single (named) wildcards for request path matching and access of the captured values from the pipeline ([#1358](https://github.com/dadrus/heimdall/issues/1358)) ([f2f6867](https://github.com/dadrus/heimdall/commit/f2f6867576b758312b1a85dc06fe52be3ae9d2ff))


### Code Refactorings

* Configuration of `signer` moved into `jwt` finalizer ([#1534](https://github.com/dadrus/heimdall/issues/1534)) ([4475745](https://github.com/dadrus/heimdall/commit/447574557d109be7f17844bc743eb9cc625427d9))
* Default rule rejects requests with encoded slashes in the path of the URL with `400 Bad Request` ([#1358](https://github.com/dadrus/heimdall/issues/1358)) ([f2f6867](https://github.com/dadrus/heimdall/commit/f2f6867576b758312b1a85dc06fe52be3ae9d2ff))
* Demo installation removed from the helm chart ([#1544](https://github.com/dadrus/heimdall/issues/1544)) ([f8770b3](https://github.com/dadrus/heimdall/commit/f8770b3bfa3599c37290677454baa4f52c12a7a7))
* Deprecated OTEL attributes replaced ([#1669](https://github.com/dadrus/heimdall/issues/1669)) ([e5ed3a5](https://github.com/dadrus/heimdall/commit/e5ed3a57f5de3164200c285a811908c7a32fbfc8))
* Made the usage of `if` clauses in authentication & authorization, and error pipelines consistent ([#1784](https://github.com/dadrus/heimdall/issues/1784)) ([2577f56](https://github.com/dadrus/heimdall/commit/2577f560b80c49e3e5a4b3da547245af98844843))
* Rule matching configuration API redesigned ([#1358](https://github.com/dadrus/heimdall/issues/1358)) ([f2f6867](https://github.com/dadrus/heimdall/commit/f2f6867576b758312b1a85dc06fe52be3ae9d2ff))
* Subject has been made immutable ([#1487](https://github.com/dadrus/heimdall/issues/1487)) ([6c4957f](https://github.com/dadrus/heimdall/commit/6c4957fd897de55de4b23563be4406423ba26b00))
* Support for `rule_path_match_prefix` on endpoint configurations for `http_endpoint` and `cloud_blob` providers has been dropped ([#1358](https://github.com/dadrus/heimdall/issues/1358)) ([f2f6867](https://github.com/dadrus/heimdall/commit/f2f6867576b758312b1a85dc06fe52be3ae9d2ff))


### Performance Improvements

* O(log(n)) time complexity for lookup of rules ([#1358](https://github.com/dadrus/heimdall/issues/1358)) ([f2f6867](https://github.com/dadrus/heimdall/commit/f2f6867576b758312b1a85dc06fe52be3ae9d2ff))


### Bug Fixes

* Corrected the placement of namespace selector properties in the Helm chart's admission controller configuration ([#1752](https://github.com/dadrus/heimdall/issues/1752)). ([4c059b3](https://github.com/dadrus/heimdall/commit/4c059b38510a1aa2d37d9103a3cb8935f4c2043b))
* Fixed a nil pointer error in the Helm chart that occurred when a deployment was configured with custom annotations due to an incorrect reference in the deployment template ([#1752](https://github.com/dadrus/heimdall/issues/1752)). ([4c059b3](https://github.com/dadrus/heimdall/commit/4c059b38510a1aa2d37d9103a3cb8935f4c2043b))
* Taking updates of certificates into account while collecting metrics ([#1534](https://github.com/dadrus/heimdall/issues/1534)) ([4475745](https://github.com/dadrus/heimdall/commit/447574557d109be7f17844bc743eb9cc625427d9))
* Updated the admission controller configuration in the Helm chart to align with the redesigned structure done in v0.12.0-alpha release of heimdall ([#1752](https://github.com/dadrus/heimdall/issues/1752)). ([4c059b3](https://github.com/dadrus/heimdall/commit/4c059b38510a1aa2d37d9103a3cb8935f4c2043b))


### Documentation

* Guide for First-Party Authentication with OpenID Connect ([#1789](https://github.com/dadrus/heimdall/issues/1789)) ([8c6b9c3](https://github.com/dadrus/heimdall/commit/8c6b9c3c4fec7cc605fc8a1058e0847e7abb3947))
* New integration guide for Envoy Gateway ([#1412](https://github.com/dadrus/heimdall/issues/1412)) ([526f381](https://github.com/dadrus/heimdall/commit/526f381c931cd58e9513716a1bc7fa9149c36e3d))
* NGING Ingress Controller guide updated to cover global integration options ([#1469](https://github.com/dadrus/heimdall/issues/1469)) ([a710a64](https://github.com/dadrus/heimdall/commit/a710a640fc1ce2cadfa37eb59a4fc0fa52c5120b))
* Traefik guide updated to cover `Ingress`, `IngressRoute` and `HTTPRoute` based integration options ([#1420](https://github.com/dadrus/heimdall/issues/1420)) ([303095e](https://github.com/dadrus/heimdall/commit/303095e204c3ea753b06a2b90171462de19b1eb4))


### Dependencies

* update golang to v1.23.1 ([#1793](https://github.com/dadrus/heimdall/issues/1793))  ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update golang.org/x/exp digest to 701f63a ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update google.golang.org/genproto/googleapis/rpc digest to 8af14fe ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update module github.com/go-playground/validator/v10 to v10.22.1 ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update module github.com/jellydator/ttlcache/v3 to v3.3.0 ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update module github.com/masterminds/sprig/v3 to v3.3.0 ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update module github.com/prometheus/client_golang to v1.20.3 ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update module github.com/redis/rueidis to v1.0.45  ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update module github.com/redis/rueidis/rueidisotel to v1.0.45  ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update module github.com/rs/cors to v1.11.1 ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update module go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc to v0.55.0 ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update module go.opentelemetry.io/contrib/instrumentation/host to v0.55.0  ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update module go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp to v0.55.0  ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update module go.opentelemetry.io/contrib/instrumentation/runtime to v0.55.0  ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update module go.opentelemetry.io/contrib/propagators/autoprop to v0.55.0 ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update module gocloud.dev to v0.39.0 ([#1774](https://github.com/dadrus/heimdall/issues/1774)) ([4ffa9e4](https://github.com/dadrus/heimdall/commit/4ffa9e45227c177ba5f729b6111d6551de5a67a8))
* update module google.golang.org/grpc to v1.66.2 ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update module k8s.io/client-go to v0.31.1  ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))
* update opentelemetry-go monorepo to v1.30.0  ([#1793](https://github.com/dadrus/heimdall/issues/1793)) ([54e6cad](https://github.com/dadrus/heimdall/commit/54e6cad5e4e8b909f646e2f0318f94388f793039))

## [0.14.5-alpha](https://github.com/dadrus/heimdall/compare/v0.14.4-alpha...v0.14.5-alpha) (2024-08-25)


### Dependencies

* update github.com/youmark/pkcs8 digest to a2c0da2 ([#1671](https://github.com/dadrus/heimdall/issues/1671)) ([ad37b99](https://github.com/dadrus/heimdall/commit/ad37b99aa94a99299a4a37e32a774a8e51099844))
* update golang to v1.23.0 ([#1711](https://github.com/dadrus/heimdall/issues/1711)) ([0a67326](https://github.com/dadrus/heimdall/commit/0a673264674f4a1d2dde18cd73825572696efc46))
* update golang.org/x/exp digest to 9b4947d ([#1724](https://github.com/dadrus/heimdall/issues/1724)) ([c9bf5dc](https://github.com/dadrus/heimdall/commit/c9bf5dcc8891f359a6bc028918084cd77273fd09))
* update google.golang.org/genproto/googleapis/rpc digest to 4ba0660 ([#1725](https://github.com/dadrus/heimdall/issues/1725)) ([661716a](https://github.com/dadrus/heimdall/commit/661716a003789c0fce4b36fdaf2eaaf8270e7187))
* update kubernetes packages to v0.31.0 ([#1708](https://github.com/dadrus/heimdall/issues/1708)) ([49a7b18](https://github.com/dadrus/heimdall/commit/49a7b18cbb3a603eee563fe116e4bbba63df115e))
* update module github.com/dlclark/regexp2 to v1.11.4 ([#1686](https://github.com/dadrus/heimdall/issues/1686)) ([e4827de](https://github.com/dadrus/heimdall/commit/e4827de8716941ef94a7f7f982fd58aa8f8826db))
* update module github.com/envoyproxy/go-control-plane to v0.13.0 ([#1716](https://github.com/dadrus/heimdall/issues/1716)) ([a06cb40](https://github.com/dadrus/heimdall/commit/a06cb40365e6529b4940e69622b5c1981b7049bf))
* update module github.com/go-jose/go-jose/v4 to v4.0.4 ([#1673](https://github.com/dadrus/heimdall/issues/1673)) ([2dfb142](https://github.com/dadrus/heimdall/commit/2dfb1422ecfe8c706a8512efc4655ec45789b092))
* update module github.com/go-viper/mapstructure/v2 to v2.1.0 ([#1702](https://github.com/dadrus/heimdall/issues/1702)) ([0115fe8](https://github.com/dadrus/heimdall/commit/0115fe806df1b31b8860b7ec91d7dcd613ccf4e1))
* update module github.com/google/cel-go to v0.21.0 ([#1684](https://github.com/dadrus/heimdall/issues/1684)) ([0601589](https://github.com/dadrus/heimdall/commit/06015891e3e88a4c023740fef0f6fd345ee2f02e))
* update module github.com/jellydator/ttlcache/v3 to v3.2.1 ([#1734](https://github.com/dadrus/heimdall/issues/1734)) ([161689d](https://github.com/dadrus/heimdall/commit/161689d0c4d260b6b3e81a43e3f849d6cc48550b))
* update module github.com/prometheus/client_golang to v1.20.2 ([#1727](https://github.com/dadrus/heimdall/issues/1727)) ([6194d6d](https://github.com/dadrus/heimdall/commit/6194d6d2430f4486779ce04d8b86f108c8d9a7a5))
* update module github.com/redis/rueidis to v1.0.44 ([#1700](https://github.com/dadrus/heimdall/issues/1700)) ([9b7c43b](https://github.com/dadrus/heimdall/commit/9b7c43b26f1aea1b0233bf25d7cbc30ea2f61394))
* update module github.com/redis/rueidis/rueidisotel to v1.0.44 ([#1701](https://github.com/dadrus/heimdall/issues/1701)) ([02731bd](https://github.com/dadrus/heimdall/commit/02731bda2b5b565236c81b50c19aa678f3b5bc18))
* update module github.com/tidwall/gjson to v1.17.3 ([#1681](https://github.com/dadrus/heimdall/issues/1681)) ([f5e1707](https://github.com/dadrus/heimdall/commit/f5e170701b7ac4ae682f8b4ef2b58f412d56e10e))
* update module go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc to v0.54.0 ([#1728](https://github.com/dadrus/heimdall/issues/1728)) ([c66e903](https://github.com/dadrus/heimdall/commit/c66e903fa57c336f12ebaa588717581da8901f63))
* update module go.opentelemetry.io/contrib/instrumentation/host to v0.54.0 ([#1729](https://github.com/dadrus/heimdall/issues/1729)) ([eef6b6e](https://github.com/dadrus/heimdall/commit/eef6b6e33cc70b3f9affd2ec9fa3e621f823ed6f))
* update module go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp to v0.54.0 ([#1730](https://github.com/dadrus/heimdall/issues/1730)) ([01865ed](https://github.com/dadrus/heimdall/commit/01865ed8324d0c1066e6ab9e0c1b07013b3b587f))
* update module go.opentelemetry.io/contrib/instrumentation/runtime to v0.54.0 ([#1731](https://github.com/dadrus/heimdall/issues/1731)) ([415953d](https://github.com/dadrus/heimdall/commit/415953df30f227d28f9032a41bf0eb45b32873d8))
* update module go.opentelemetry.io/contrib/propagators/autoprop to v0.54.0 ([#1732](https://github.com/dadrus/heimdall/issues/1732)) ([3f6edea](https://github.com/dadrus/heimdall/commit/3f6edea788b55efdf64b41779d3c9b46346d8e89))
* update module go.uber.org/fx to v1.22.2 ([#1694](https://github.com/dadrus/heimdall/issues/1694)) ([810d995](https://github.com/dadrus/heimdall/commit/810d995e4a5611ce4aaabc9f8e71e1a8d03a7208))
* update module gocloud.dev to v0.38.0 ([#1735](https://github.com/dadrus/heimdall/issues/1735)) ([b32d5c0](https://github.com/dadrus/heimdall/commit/b32d5c0b73df4d3f6221691752bfef06854b56d7))
* update opentelemetry-go monorepo to v1.29.0 ([#1733](https://github.com/dadrus/heimdall/issues/1733)) ([e093267](https://github.com/dadrus/heimdall/commit/e093267d36ab7b17e8e6c825ef0e526d7ae903b9))

## [0.14.4-alpha](https://github.com/dadrus/heimdall/compare/v0.14.3-alpha...v0.14.4-alpha) (2024-07-25)


### Bug Fixes

* OAuth2 `iss` claim verification in JWT/OIDC authenticators when used with `metadata_endpoint` ([#1660](https://github.com/dadrus/heimdall/issues/1660)) by [@martin31821](https://github.com/martin31821) ([a9947f2](https://github.com/dadrus/heimdall/commit/a9947f20f412ca4133202ee7bc1e7b58f2903766))
* Trailing useless bytes ignored while parsing PEM content ([#1564](https://github.com/dadrus/heimdall/issues/1564)) ([0c52bd3](https://github.com/dadrus/heimdall/commit/0c52bd30d308dbd8985f3223ba36180dbb808a24))


### Dependencies

* update golang to v1.22.5 ([#1592](https://github.com/dadrus/heimdall/issues/1592)) ([1d4de85](https://github.com/dadrus/heimdall/commit/1d4de852f26bb39584e312a4d4cf2201c4606f83))
* update golang.org/x/exp digest to 8a7402a ([#1644](https://github.com/dadrus/heimdall/issues/1644)) ([6fbbf15](https://github.com/dadrus/heimdall/commit/6fbbf154f67664f8690a76dc05c1addd5628c907))
* update google.golang.org/genproto/googleapis/rpc digest to e6d459c ([#1654](https://github.com/dadrus/heimdall/issues/1654)) ([103c1ac](https://github.com/dadrus/heimdall/commit/103c1ac0a5c909d8bbc619e7d4bd7aa74a081485))
* update kubernetes packages to v0.30.2 ([#1540](https://github.com/dadrus/heimdall/issues/1540)) ([70fdd62](https://github.com/dadrus/heimdall/commit/70fdd62de11790b9f4310282a2eb55ee2f8f94d4))
* update module github.com/dlclark/regexp2 to v1.11.2 ([#1630](https://github.com/dadrus/heimdall/issues/1630)) ([afd7c92](https://github.com/dadrus/heimdall/commit/afd7c92ef2520e9319437a178ad2c4e293b103b7))
* update module github.com/go-co-op/gocron/v2 to v2.11.0 ([#1645](https://github.com/dadrus/heimdall/issues/1645)) ([42688aa](https://github.com/dadrus/heimdall/commit/42688aaeb5ab18fd80a7cabe15f41a1cda075d29))
* update module github.com/go-jose/go-jose/v4 to v4.0.3 ([#1625](https://github.com/dadrus/heimdall/issues/1625)) ([59caff8](https://github.com/dadrus/heimdall/commit/59caff8418eb1190c0320761d797fc2faceaf2ce))
* update module github.com/go-playground/validator/v10 to v10.22.0 ([#1537](https://github.com/dadrus/heimdall/issues/1537)) ([1f6eeaa](https://github.com/dadrus/heimdall/commit/1f6eeaa1425749007a9aa6f19f2ce8cc3413aa62))
* update module github.com/redis/rueidis to v1.0.41 ([#1617](https://github.com/dadrus/heimdall/issues/1617)) ([3919aaf](https://github.com/dadrus/heimdall/commit/3919aafd286b315530fa7cb2cfa4bb6692d4d364))
* update module github.com/redis/rueidis/rueidisotel to v1.0.41 ([#1619](https://github.com/dadrus/heimdall/issues/1619)) ([69bc2aa](https://github.com/dadrus/heimdall/commit/69bc2aa29615f968eb2a23d1bb3111495597d2e5))
* update module github.com/spf13/cobra to v1.8.1 ([#1551](https://github.com/dadrus/heimdall/issues/1551)) ([871ee91](https://github.com/dadrus/heimdall/commit/871ee915648bd7d1070414bcf4f0ee46665de216))
* update module github.com/tonglil/opentelemetry-go-datadog-propagator to v0.1.3 ([#1579](https://github.com/dadrus/heimdall/issues/1579)) ([27c1026](https://github.com/dadrus/heimdall/commit/27c10260d18647ad1dbb7624b3148fd4c4f36d3a))
* update module github.com/wi2l/jsondiff to v0.6.0 ([#1558](https://github.com/dadrus/heimdall/issues/1558)) ([c4cfd07](https://github.com/dadrus/heimdall/commit/c4cfd078bd5811395d3728a27aae6ddefe628c6a))
* update module go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc to v0.53.0 ([#1600](https://github.com/dadrus/heimdall/issues/1600)) ([84b330f](https://github.com/dadrus/heimdall/commit/84b330f76ca67391f6b27fa1b1d00943145cc056))
* update module go.opentelemetry.io/contrib/instrumentation/host to v0.53.0 ([#1601](https://github.com/dadrus/heimdall/issues/1601)) ([31834e0](https://github.com/dadrus/heimdall/commit/31834e0b21504c78ead506acea9af19a221bed55))
* update module go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp to v0.53.0 ([#1602](https://github.com/dadrus/heimdall/issues/1602)) ([d3d2328](https://github.com/dadrus/heimdall/commit/d3d2328c4a23d2aca6dc959386e5f3c865b42691))
* update module go.opentelemetry.io/contrib/instrumentation/runtime to v0.53.0 ([#1603](https://github.com/dadrus/heimdall/issues/1603)) ([b23bc0b](https://github.com/dadrus/heimdall/commit/b23bc0be499ffebfc19d4fdd500f605b7d4b1346))
* update module go.opentelemetry.io/contrib/propagators/autoprop to v0.53.0 ([#1604](https://github.com/dadrus/heimdall/issues/1604)) ([f8679e9](https://github.com/dadrus/heimdall/commit/f8679e948308976be620817e954f365073e71c20))
* update module go.uber.org/fx to v1.22.1 ([#1577](https://github.com/dadrus/heimdall/issues/1577)) ([49ab1c2](https://github.com/dadrus/heimdall/commit/49ab1c2336e31a01dbf04516ac505a1b7e48c174))
* update module google.golang.org/grpc to v1.65.0 ([#1589](https://github.com/dadrus/heimdall/issues/1589)) ([dad8e53](https://github.com/dadrus/heimdall/commit/dad8e531511b79ab2cd085b49214a1b45ba8254a))
* update module google.golang.org/protobuf to v1.34.2 ([#1535](https://github.com/dadrus/heimdall/issues/1535)) ([12aa205](https://github.com/dadrus/heimdall/commit/12aa205e8c7f2c61f2ce0540fb5fa9be718a8cbb))
* update module k8s.io/api to v0.30.3 ([#1640](https://github.com/dadrus/heimdall/issues/1640)) ([9b2e072](https://github.com/dadrus/heimdall/commit/9b2e0727ef6e7b15cc03fc9417ef2c7744099ccc))
* update module k8s.io/client-go to v0.30.3 ([#1641](https://github.com/dadrus/heimdall/issues/1641)) ([333c81f](https://github.com/dadrus/heimdall/commit/333c81f877dcf07993e6dbe319487a221015da4d))
* update module k8s.io/klog/v2 to v2.130.1 ([#1567](https://github.com/dadrus/heimdall/issues/1567)) ([d16ecbe](https://github.com/dadrus/heimdall/commit/d16ecbeb7b1f360196d1c02ee77dad148c5fc9a4))
* update opentelemetry-go monorepo to v1.28.0 ([#1591](https://github.com/dadrus/heimdall/issues/1591)) ([a33f586](https://github.com/dadrus/heimdall/commit/a33f586cd0f3760c900fa946c435ed34ad4414e5))

## [0.14.3-alpha](https://github.com/dadrus/heimdall/compare/v0.14.2-alpha...v0.14.3-alpha) (2024-06-09)


### Dependencies

* update golang to v1.22.4 ([#1517](https://github.com/dadrus/heimdall/issues/1517)) ([a86784a](https://github.com/dadrus/heimdall/commit/a86784aa99def6ab756cd3dd9beece52c673f88b))
* update golang.org/x/exp digest to fc45aab ([#1515](https://github.com/dadrus/heimdall/issues/1515)) ([f07ae39](https://github.com/dadrus/heimdall/commit/f07ae391022bd2044058be5ea2bd7e56e0780998))
* update google.golang.org/genproto/googleapis/rpc digest to ef581f9 ([#1516](https://github.com/dadrus/heimdall/issues/1516)) ([acc5740](https://github.com/dadrus/heimdall/commit/acc574013f5e8609704e9b847eec6cba2e594185))
* update kubernetes packages to v0.30.1 ([#1466](https://github.com/dadrus/heimdall/issues/1466)) ([dc68e5e](https://github.com/dadrus/heimdall/commit/dc68e5e27d78cff06edf14f32b244b5c1589fcbc))
* update module github.com/go-jose/go-jose/v4 to v4.0.2 ([#1450](https://github.com/dadrus/heimdall/issues/1450)) ([1aba621](https://github.com/dadrus/heimdall/commit/1aba6213de16a6ad36e3a2726844371df1b3cb2a))
* update module github.com/go-playground/validator/v10 to v10.21.0 ([#1509](https://github.com/dadrus/heimdall/issues/1509)) ([0c9167e](https://github.com/dadrus/heimdall/commit/0c9167ea910e780af9849824ad8a624193d0849e))
* update module github.com/go-viper/mapstructure/v2 to v2.0.0 ([#1510](https://github.com/dadrus/heimdall/issues/1510)) ([d7224ff](https://github.com/dadrus/heimdall/commit/d7224ff66d6a11574898926394608ad0a3bffe8d))
* update module github.com/goccy/go-json to v0.10.3 ([#1476](https://github.com/dadrus/heimdall/issues/1476)) ([32f5eca](https://github.com/dadrus/heimdall/commit/32f5eca3fe2dae80d58c6a88d3e8fb65d1d5680d))
* update module github.com/redis/rueidis to v1.0.38 ([#1502](https://github.com/dadrus/heimdall/issues/1502)) ([91569ee](https://github.com/dadrus/heimdall/commit/91569ee8da7f3c80880754c473378d52c1a07485))
* update module github.com/redis/rueidis/rueidisotel to v1.0.38 ([#1503](https://github.com/dadrus/heimdall/issues/1503)) ([63dec15](https://github.com/dadrus/heimdall/commit/63dec151781a4daf0808f8b18ca15bfdce8babb0))
* update module github.com/rs/zerolog to v1.33.0 ([#1490](https://github.com/dadrus/heimdall/issues/1490)) ([9579381](https://github.com/dadrus/heimdall/commit/957938154a2369750d58c1f30b78d7e04790beeb))
* update module github.com/santhosh-tekuri/jsonschema/v6 to v6.0.1 ([#1520](https://github.com/dadrus/heimdall/issues/1520)) ([3648c59](https://github.com/dadrus/heimdall/commit/3648c597a6ce5d1086e9f1fc25bc6bcf642d2535))
* update module go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc to v0.52.0 ([#1478](https://github.com/dadrus/heimdall/issues/1478)) ([535aa2f](https://github.com/dadrus/heimdall/commit/535aa2f61ae1459b7b0c7d001e05607e863acd6b))
* update module go.opentelemetry.io/contrib/instrumentation/host to v0.52.0 ([#1480](https://github.com/dadrus/heimdall/issues/1480)) ([509d4b3](https://github.com/dadrus/heimdall/commit/509d4b3608f0758f0c556f4cfc559a83e547b8f4))
* update module go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp to v0.52.0 ([#1482](https://github.com/dadrus/heimdall/issues/1482)) ([b112767](https://github.com/dadrus/heimdall/commit/b112767a68c5c824ca02b8825f0934ac9d2b0aed))
* update module go.opentelemetry.io/contrib/instrumentation/runtime to v0.52.0 ([#1483](https://github.com/dadrus/heimdall/issues/1483)) ([4c8707c](https://github.com/dadrus/heimdall/commit/4c8707cae3d050a45bed9dd1226c97c1d52e0d1d))
* update module go.opentelemetry.io/contrib/propagators/autoprop to v0.52.0 ([#1484](https://github.com/dadrus/heimdall/issues/1484)) ([57c5a6a](https://github.com/dadrus/heimdall/commit/57c5a6a3757e4e01714ca1295b247f836771e095))
* update module go.opentelemetry.io/otel to v1.27.0 ([#1481](https://github.com/dadrus/heimdall/issues/1481)) ([384612e](https://github.com/dadrus/heimdall/commit/384612e595a3ef47865ed06efa0c3e74d54cc791))
* update module go.opentelemetry.io/otel/bridge/opentracing to v1.27.0 ([#1481](https://github.com/dadrus/heimdall/issues/1481)) ([384612e](https://github.com/dadrus/heimdall/commit/384612e595a3ef47865ed06efa0c3e74d54cc791))
* update module go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc to v1.27.0 ([#1481](https://github.com/dadrus/heimdall/issues/1481)) ([384612e](https://github.com/dadrus/heimdall/commit/384612e595a3ef47865ed06efa0c3e74d54cc791))
* update module go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp to v1.27.0 ([#1481](https://github.com/dadrus/heimdall/issues/1481)) ([384612e](https://github.com/dadrus/heimdall/commit/384612e595a3ef47865ed06efa0c3e74d54cc791))
* update module go.opentelemetry.io/otel/exporters/otlp/otlptrace to v1.27.0 ([#1481](https://github.com/dadrus/heimdall/issues/1481)) ([384612e](https://github.com/dadrus/heimdall/commit/384612e595a3ef47865ed06efa0c3e74d54cc791))
* update module go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc to v1.27.0 ([#1481](https://github.com/dadrus/heimdall/issues/1481)) ([384612e](https://github.com/dadrus/heimdall/commit/384612e595a3ef47865ed06efa0c3e74d54cc791))
* update module go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttpto to v1.27.0 ([#1481](https://github.com/dadrus/heimdall/issues/1481)) ([384612e](https://github.com/dadrus/heimdall/commit/384612e595a3ef47865ed06efa0c3e74d54cc791))
* update module go.opentelemetry.io/otel/exporters/prometheus to v0.49.0 ([#1481](https://github.com/dadrus/heimdall/issues/1481)) ([384612e](https://github.com/dadrus/heimdall/commit/384612e595a3ef47865ed06efa0c3e74d54cc791))
* update module go.opentelemetry.io/otel/exporters/zipkin to v1.27.0 ([#1481](https://github.com/dadrus/heimdall/issues/1481)) ([384612e](https://github.com/dadrus/heimdall/commit/384612e595a3ef47865ed06efa0c3e74d54cc791))
* update module go.opentelemetry.io/otel/metric to v1.27.0 ([#1481](https://github.com/dadrus/heimdall/issues/1481)) ([384612e](https://github.com/dadrus/heimdall/commit/384612e595a3ef47865ed06efa0c3e74d54cc791))
* update module go.opentelemetry.io/otel/sdk to v1.27.0 ([#1481](https://github.com/dadrus/heimdall/issues/1481)) ([384612e](https://github.com/dadrus/heimdall/commit/384612e595a3ef47865ed06efa0c3e74d54cc791))
* update module go.opentelemetry.io/otel/sdk/metric to v1.27.0 ([#1481](https://github.com/dadrus/heimdall/issues/1481)) ([384612e](https://github.com/dadrus/heimdall/commit/384612e595a3ef47865ed06efa0c3e74d54cc791))
* update module go.opentelemetry.io/otel/trace to v1.27.0 ([#1481](https://github.com/dadrus/heimdall/issues/1481)) ([384612e](https://github.com/dadrus/heimdall/commit/384612e595a3ef47865ed06efa0c3e74d54cc791))
* update module go.uber.org/fx to v1.22.0 ([#1501](https://github.com/dadrus/heimdall/issues/1501)) ([37ddf79](https://github.com/dadrus/heimdall/commit/37ddf7945f76d91d5ac6e2abeaf09d48129a4082))
* update module google.golang.org/grpc to v1.64.0 ([#1462](https://github.com/dadrus/heimdall/issues/1462)) ([9d5e47c](https://github.com/dadrus/heimdall/commit/9d5e47ca527b8ff266da4eccf5a1184b4818f540))

## [0.14.2-alpha](https://github.com/dadrus/heimdall/compare/v0.14.1-alpha...v0.14.2-alpha) (2024-05-12)


### Dependencies

* update golang to v1.22.3 ([#1428](https://github.com/dadrus/heimdall/issues/1428)) ([524a3d4](https://github.com/dadrus/heimdall/commit/524a3d40f14b80f66a4a8d3e31d12be67ffb094c))
* update kubernetes packages to v0.30.0 ([#1368](https://github.com/dadrus/heimdall/issues/1368)) ([04cba69](https://github.com/dadrus/heimdall/commit/04cba6957a2e34175c71dbd8e486626658633964))
* update module github.com/go-co-op/gocron/v2 to v2.5.0 ([#1424](https://github.com/dadrus/heimdall/issues/1424)) ([c3449a0](https://github.com/dadrus/heimdall/commit/c3449a00b4cc2be23fa029dae12428a2c1fe3a71))
* update module github.com/go-playground/validator/v10 to v10.20.0 ([#1402](https://github.com/dadrus/heimdall/issues/1402)) ([a965ef0](https://github.com/dadrus/heimdall/commit/a965ef038ae20ab04b23bb4fb36d603bd3989846))
* update module github.com/prometheus/client_golang to v1.19.1 ([#1434](https://github.com/dadrus/heimdall/issues/1434)) ([d778e9c](https://github.com/dadrus/heimdall/commit/d778e9c67cd20608a94d9b6edd10c26c66bf0339))
* update module github.com/redis/rueidis to v1.0.37 ([#1440](https://github.com/dadrus/heimdall/issues/1440)) ([ce2e65b](https://github.com/dadrus/heimdall/commit/ce2e65b3ee5958277d71e2b446475edcb8afa798))
* update module github.com/redis/rueidis/rueidisotel to v1.0.37 ([#1441](https://github.com/dadrus/heimdall/issues/1441)) ([5c163b5](https://github.com/dadrus/heimdall/commit/5c163b5195f8b447d4924188d860ad10f2fa0203))
* update module github.com/rs/cors to v1.11.0 ([#1383](https://github.com/dadrus/heimdall/issues/1383)) ([b44b9c0](https://github.com/dadrus/heimdall/commit/b44b9c0b16a2137b05c4d0873bc32d0665663585))
* update module github.com/wi2l/jsondiff to v0.5.2 ([#1370](https://github.com/dadrus/heimdall/issues/1370)) ([fd0cb04](https://github.com/dadrus/heimdall/commit/fd0cb046af087b09242547a9e4b4ada23f9e8c96))
* update module github.com/youmark/pkcs8 to v0.0.0-20240424034433-3c2c7870ae76 ([#1407](https://github.com/dadrus/heimdall/issues/1407)) ([587f073](https://github.com/dadrus/heimdall/commit/587f07364e96d3e3e96688c140f344568a76af7e))
* update module go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc to v0.51.0 ([#1387](https://github.com/dadrus/heimdall/issues/1387)) ([ce65b02](https://github.com/dadrus/heimdall/commit/ce65b025d9422b76b6b81eab2ee741bf572800be))
* update module go.opentelemetry.io/contrib/instrumentation/host to v0.51.0 ([#1389](https://github.com/dadrus/heimdall/issues/1389)) ([5688d8f](https://github.com/dadrus/heimdall/commit/5688d8fb9fddc2fca8e1f05fb935446c24be02e1))
* update module go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp to v0.51.0 ([#1390](https://github.com/dadrus/heimdall/issues/1390)) ([2357888](https://github.com/dadrus/heimdall/commit/23578889f6ec8911832b4b1a484d00e66e1e8d8d))
* update module go.opentelemetry.io/contrib/instrumentation/runtime to v0.51.0 ([#1391](https://github.com/dadrus/heimdall/issues/1391)) ([a58f629](https://github.com/dadrus/heimdall/commit/a58f629f096f3b5d67e28d32f8fb5daf49e25e9d))
* update module go.opentelemetry.io/contrib/propagators/autoprop to v0.51.0 ([#1392](https://github.com/dadrus/heimdall/issues/1392)) ([fc87ef5](https://github.com/dadrus/heimdall/commit/fc87ef5c7107b083fa6f9322901b1adfb7c53fc0))
* update module go.opentelemetry.io/otel to v1.26.0 ([#1385](https://github.com/dadrus/heimdall/issues/1385)) ([3c531d7](https://github.com/dadrus/heimdall/commit/3c531d72813951c1e1b7b4d73cfa1b1c28e27edc))
* update module go.opentelemetry.io/otel/bridge/opentracing to v1.26.0 ([#1385](https://github.com/dadrus/heimdall/issues/1385)) ([3c531d7](https://github.com/dadrus/heimdall/commit/3c531d72813951c1e1b7b4d73cfa1b1c28e27edc))
* update module go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc to v1.26.0 ([#1385](https://github.com/dadrus/heimdall/issues/1385)) ([3c531d7](https://github.com/dadrus/heimdall/commit/3c531d72813951c1e1b7b4d73cfa1b1c28e27edc))
* update module go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp to v1.26.0 ([#1385](https://github.com/dadrus/heimdall/issues/1385)) ([3c531d7](https://github.com/dadrus/heimdall/commit/3c531d72813951c1e1b7b4d73cfa1b1c28e27edc))
* update module go.opentelemetry.io/otel/exporters/otlp/otlptrace to v1.26.0 ([#1385](https://github.com/dadrus/heimdall/issues/1385)) ([3c531d7](https://github.com/dadrus/heimdall/commit/3c531d72813951c1e1b7b4d73cfa1b1c28e27edc))
* update module go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc to v1.26.0 ([#1385](https://github.com/dadrus/heimdall/issues/1385)) ([3c531d7](https://github.com/dadrus/heimdall/commit/3c531d72813951c1e1b7b4d73cfa1b1c28e27edc))
* update module go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp to v1.26.0 ([#1385](https://github.com/dadrus/heimdall/issues/1385)) ([3c531d7](https://github.com/dadrus/heimdall/commit/3c531d72813951c1e1b7b4d73cfa1b1c28e27edc))
* update module go.opentelemetry.io/otel/exporters/prometheus to v0.48.0 ([#1385](https://github.com/dadrus/heimdall/issues/1385)) ([3c531d7](https://github.com/dadrus/heimdall/commit/3c531d72813951c1e1b7b4d73cfa1b1c28e27edc))
* update module go.opentelemetry.io/otel/exporters/zipkin to v1.26.0 ([#1385](https://github.com/dadrus/heimdall/issues/1385)) ([3c531d7](https://github.com/dadrus/heimdall/commit/3c531d72813951c1e1b7b4d73cfa1b1c28e27edc))
* update module go.opentelemetry.io/otel/metric to v1.26.0 ([#1385](https://github.com/dadrus/heimdall/issues/1385)) ([3c531d7](https://github.com/dadrus/heimdall/commit/3c531d72813951c1e1b7b4d73cfa1b1c28e27edc))
* update module go.opentelemetry.io/otel/sdk to v1.26.0 ([#1385](https://github.com/dadrus/heimdall/issues/1385)) ([3c531d7](https://github.com/dadrus/heimdall/commit/3c531d72813951c1e1b7b4d73cfa1b1c28e27edc))
* update module go.opentelemetry.io/otel/sdk/metric to v1.26.0 ([#1385](https://github.com/dadrus/heimdall/issues/1385)) ([3c531d7](https://github.com/dadrus/heimdall/commit/3c531d72813951c1e1b7b4d73cfa1b1c28e27edc))
* update module go.opentelemetry.io/otel/trace to v1.26.0 ([#1385](https://github.com/dadrus/heimdall/issues/1385)) ([3c531d7](https://github.com/dadrus/heimdall/commit/3c531d72813951c1e1b7b4d73cfa1b1c28e27edc))
* update module go.uber.org/fx to v1.21.1 ([#1384](https://github.com/dadrus/heimdall/issues/1384)) ([614117f](https://github.com/dadrus/heimdall/commit/614117fc53d1dbe6ff4cba09265b06e83dafcf21))
* update module golang.org/x/exp to v0.0.0-20240506185415-9bf2ced13842 ([#1422](https://github.com/dadrus/heimdall/issues/1422)) ([561ee65](https://github.com/dadrus/heimdall/commit/561ee6559c488e9770eee1e7ff9a6cdd6faf1cc5))
* update module google.golang.org/genproto/googleapis/rpc to v0.0.0-20240509183442-62759503f434 ([#1436](https://github.com/dadrus/heimdall/issues/1436)) ([508e22b](https://github.com/dadrus/heimdall/commit/508e22bd7657a5f8e452a7f78a7811c2eea5b908))
* update module google.golang.org/protobuf to v1.34.1 ([#1421](https://github.com/dadrus/heimdall/issues/1421)) ([e25b077](https://github.com/dadrus/heimdall/commit/e25b077ce13c6a90bd33ea90e1a6191f311f1a63))

## [0.14.1-alpha](https://github.com/dadrus/heimdall/compare/v0.14.0-alpha...v0.14.1-alpha) (2024-04-09)


### Dependencies

* update golang to v1.22.2 ([#1313](https://github.com/dadrus/heimdall/issues/1313)) ([7c37100](https://github.com/dadrus/heimdall/commit/7c3710058d3936dac367f84b5a317e6f7dd24d80))
* update golang.org/x/exp digest to c0f41cb ([#1318](https://github.com/dadrus/heimdall/issues/1318)) ([723ad16](https://github.com/dadrus/heimdall/commit/723ad164930021a86ffa19c2ac62421a0c1f015f))
* update module github.com/knadh/koanf/v2 to v2.1.1 ([#1308](https://github.com/dadrus/heimdall/issues/1308)) ([502cdcb](https://github.com/dadrus/heimdall/commit/502cdcb0a78f60238e11b4be70590692907ee894))
* update module go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc to v0.50.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/contrib/instrumentation/host to v0.50.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp to v0.50.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/contrib/instrumentation/runtime to v0.50.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/contrib/propagators/autoprop to v0.50.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/otel to v1.25.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/otel/bridge/opentracing to v1.25.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc to v1.25.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp to v1.25.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/otel/exporters/otlp/otlptrace to v1.25.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc to v1.25.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp to v1.25.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/otel/exporters/prometheus to v0.47.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/otel/exporters/zipkin to v1.25.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/otel/metric to v1.25.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/otel/sdk to v1.25.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/otel/sdk/metric to v1.25.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module go.opentelemetry.io/otel/trace to v1.25.0 ([#1329](https://github.com/dadrus/heimdall/issues/1329)) ([dbb40bd](https://github.com/dadrus/heimdall/commit/dbb40bddc7399765a0759a84966300765c184ee7))
* update module google.golang.org/grpc to v1.63.2 ([#1339](https://github.com/dadrus/heimdall/issues/1339)) ([8ee3942](https://github.com/dadrus/heimdall/commit/8ee3942c9b4a2a65a6ae80e1919ce1e9126a2f2e))

## [0.14.0-alpha](https://github.com/dadrus/heimdall/compare/v0.13.0-alpha...v0.14.0-alpha) (2024-04-02)


### Features

* `env` settings in helm chart extended to support ConfigMaps, Secrets and Pod configuration in addition to string literals ([#1128](https://github.com/dadrus/heimdall/issues/1128)) by [@martin31821](https://github.com/martin31821) ([bf75c97](https://github.com/dadrus/heimdall/commit/bf75c97de9346169acbc2a9496fb7756814a5e60))
* Helm chart supports setting environment variables by referencing either a ConfigMap or a Secret via `envFrom` ([#1128](https://github.com/dadrus/heimdall/issues/1128)) by [@martin31821](https://github.com/martin31821)  ([bf75c97](https://github.com/dadrus/heimdall/commit/bf75c97de9346169acbc2a9496fb7756814a5e60))
* Hot reloading of Signer keys store ([#1232](https://github.com/dadrus/heimdall/issues/1232)) ([36076e1](https://github.com/dadrus/heimdall/commit/36076e1de864d969b1a23d9c4cd3e7cbfab4a38e))
* Hot reloading of TLS key stores ([#1230](https://github.com/dadrus/heimdall/issues/1230)) ([9abf723](https://github.com/dadrus/heimdall/commit/9abf7232725534afca0aa62b48d3aef70a3a9ea5))
* Redis as (distributed) cache ([#999](https://github.com/dadrus/heimdall/issues/999)) by [@tk-innoq](https://github.com/tk-innoq) ([2f9ba81](https://github.com/dadrus/heimdall/commit/2f9ba816b37268c1348ffa6632d6a038905c8474))


### Bug Fixes

* `audience` assertion adheres to RFC-7519, section 4.1.3 ([#1237](https://github.com/dadrus/heimdall/issues/1237)) ([560a470](https://github.com/dadrus/heimdall/commit/560a470c5ce89e964065918b9369780ab0a6ba36))
* Rule set, the rule is loaded from, is considered while updating or deleting rules ([#1298](https://github.com/dadrus/heimdall/issues/1298)) ([e571248](https://github.com/dadrus/heimdall/commit/e5712485d52b0c169964a634ab1ac33631075c84))


### Documentation

* Contour integration guide updated to cover global configuration in addition to the route based one ([#1253](https://github.com/dadrus/heimdall/issues/1253)) ([74bcebd](https://github.com/dadrus/heimdall/commit/74bcebd2cafb93c609c17b16c626cfa2148ad8ea))
* Documentation restructured to make it more comprehensive ([#1075](https://github.com/dadrus/heimdall/issues/1075)) by [@godrin](https://github.com/godrin), @REABMAX, @Ebano and @KieronWiltshire ([6612633](https://github.com/dadrus/heimdall/commit/66126336e34a388bceb82d9c79bde84bc0735918))
* HAProxy guide updated to cover global integration with the Ingress Controller ([#1240](https://github.com/dadrus/heimdall/issues/1240)) ([ed27797](https://github.com/dadrus/heimdall/commit/ed27797fc2be0c804c7da28dad3c0b6203193b13))
* Integration guide for OpenFGA ([#1299](https://github.com/dadrus/heimdall/issues/1299)) ([1d8bea2](https://github.com/dadrus/heimdall/commit/1d8bea2b2945f895467e0e28e4f16df5c5942f47))
* Traefik integration guide updated to cover global configuration in addition to the route based one ([#1269](https://github.com/dadrus/heimdall/issues/1269)) ([73b1d4c](https://github.com/dadrus/heimdall/commit/73b1d4cc0a9242597a700054271ef5d0c006855b))


### Dependencies

* update golang to 1.22.1 ([#1219](https://github.com/dadrus/heimdall/issues/1219)) ([4449cb7](https://github.com/dadrus/heimdall/commit/4449cb7384c4b76aec596d06ec64477ebc1b5fa3))
* update golang.org/x/exp digest to a685a6e ([#1245](https://github.com/dadrus/heimdall/issues/1245)) ([41ba4a2](https://github.com/dadrus/heimdall/commit/41ba4a2a9b2737e11f4f455cb68fa353a0bbff9a))
* update google.golang.org/genproto/googleapis/rpc digest to c3f9821 ([#1301](https://github.com/dadrus/heimdall/issues/1301)) ([4ccf593](https://github.com/dadrus/heimdall/commit/4ccf5932cc49176dd7de520dc9da583ddaab6b29))
* update kubernetes packages to v0.29.3 ([#1249](https://github.com/dadrus/heimdall/issues/1249)) ([43f3233](https://github.com/dadrus/heimdall/commit/43f32335752c8d85cba61eb2a74827274e2a6d84))
* update module github.com/dlclark/regexp2 to v1.11.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module github.com/evanphx/json-patch/v5 to v5.9.0 ([#1156](https://github.com/dadrus/heimdall/issues/1156)) ([3770509](https://github.com/dadrus/heimdall/commit/377050997851d2360948484def70916c1771ff60))
* update module github.com/go-co-op/gocron/v2 to v2.2.9 ([#1292](https://github.com/dadrus/heimdall/issues/1292)) ([3555329](https://github.com/dadrus/heimdall/commit/35553294290871fe13ae078b46894114be615a2a))
* update module github.com/go-jose/go-jose/v4 to v4.0.1 [security] ([#1225](https://github.com/dadrus/heimdall/issues/1225)) ([45e5a46](https://github.com/dadrus/heimdall/commit/45e5a46aea979cc5dfe6d85369e600c01b032e7d))
* update module github.com/go-playground/validator/v10 to v10.19.0 ([#1217](https://github.com/dadrus/heimdall/issues/1217)) ([564d256](https://github.com/dadrus/heimdall/commit/564d256a44f25e464dcfbee35d93b512b92fcbe3))
* update module github.com/google/cel-go to v0.20.1 ([#1224](https://github.com/dadrus/heimdall/issues/1224)) ([a0669a8](https://github.com/dadrus/heimdall/commit/a0669a818b0454f9e5f675502e41402acf991daf))
* update module github.com/google/uuid to v1.6.0 ([#1151](https://github.com/dadrus/heimdall/issues/1151)) ([5f9dc9c](https://github.com/dadrus/heimdall/commit/5f9dc9c819a7a3454dc2b1f13ffb1c6c41648114))
* update module github.com/grpc-ecosystem/go-grpc-middleware/v2 to v2.1.0 ([#1241](https://github.com/dadrus/heimdall/issues/1241)) ([bff3874](https://github.com/dadrus/heimdall/commit/bff38740dd16d63b11a1ff4f2df4db647a43511a))
* update module github.com/jellydator/ttlcache/v3 to v3.2.0 ([#1198](https://github.com/dadrus/heimdall/issues/1198)) ([7c560d2](https://github.com/dadrus/heimdall/commit/7c560d21835527537afcb8704cd882220a14d61d))
* update module github.com/knadh/koanf/v2 to v2.1.0 ([#1178](https://github.com/dadrus/heimdall/issues/1178)) ([1e344d3](https://github.com/dadrus/heimdall/commit/1e344d383954cdd2daecce5ea190983f4fcb8d89))
* update module github.com/ory/ladon to v1.3.0 ([#1222](https://github.com/dadrus/heimdall/issues/1222)) ([3ca9ec4](https://github.com/dadrus/heimdall/commit/3ca9ec4b594d620428fa8fd2af7c31a8152d55c4))
* update module github.com/prometheus/client_golang to v1.19.0 ([#1212](https://github.com/dadrus/heimdall/issues/1212)) ([256932f](https://github.com/dadrus/heimdall/commit/256932fea84666bb1814661f18cf0448bbd52190))
* update module github.com/rs/zerolog to v1.32.0 ([#1165](https://github.com/dadrus/heimdall/issues/1165)) ([d4678f6](https://github.com/dadrus/heimdall/commit/d4678f60e95d82e2066f1195fd66dadac469b597))
* update module github.com/tidwall/gjson to v1.17.1 ([#1187](https://github.com/dadrus/heimdall/issues/1187)) ([a1680a1](https://github.com/dadrus/heimdall/commit/a1680a13db5d3edd9d3c24ab86951a1960e70922))
* update module github.com/tonglil/opentelemetry-go-datadog-propagator to v0.1.2 ([#1215](https://github.com/dadrus/heimdall/issues/1215)) ([0d2a6ce](https://github.com/dadrus/heimdall/commit/0d2a6cefef99b7b49ecf6f14c6677e574b07e69f))
* update module go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc to v0.49.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/contrib/instrumentation/host to v0.49.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp to v0.49.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/contrib/instrumentation/runtime to v0.49.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/contrib/propagators/autoprop to v0.49.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/otel to v1.24.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/otel/bridge/opentracing to v1.24.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc to v1.24.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp to v1.24.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/otel/exporters/otlp/otlptrace to v1.24.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc to v1.24.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp to v1.24.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/otel/exporters/prometheus to v0.46.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/otel/exporters/zipkin to v1.24.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/otel/metric to v1.24.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/otel/sdk to v1.24.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/otel/sdk/metric to v1.24.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.opentelemetry.io/otel/trace to v1.24.0 ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module go.uber.org/fx to v1.21.0 ([#1244](https://github.com/dadrus/heimdall/issues/1244)) ([99963e0](https://github.com/dadrus/heimdall/commit/99963e0232a4246fb37a61dd2500fdc7efac08ac))
* update module gocloud.dev to v0.37.0 ([#1236](https://github.com/dadrus/heimdall/issues/1236)) ([8d1c7fe](https://github.com/dadrus/heimdall/commit/8d1c7feaeefac6109b8c7c01188dfea268a251a7))
* update module google.golang.org/genproto/googleapis/rpc to b0ce06b ([#1209](https://github.com/dadrus/heimdall/issues/1209)) ([c51eda9](https://github.com/dadrus/heimdall/commit/c51eda927d4587560cd1cf17f1547488c01d15dd))
* update module google.golang.org/grpc to v1.62.1 ([#1220](https://github.com/dadrus/heimdall/issues/1220)) ([d22d0d2](https://github.com/dadrus/heimdall/commit/d22d0d2626a8c67c8e3b728fd82e1aa298746b9c))
* update module google.golang.org/protobuf to v1.33.0 ([#1221](https://github.com/dadrus/heimdall/issues/1221)) ([e2dab94](https://github.com/dadrus/heimdall/commit/e2dab9456fd4f1f5a265a6106858610da33fb995))
* update module k8s.io/klog/v2 to v2.120.1 ([#1139](https://github.com/dadrus/heimdall/issues/1139)) ([541828b](https://github.com/dadrus/heimdall/commit/541828bbcfd0d838a1349a27951514a2c439bab4))

## [0.13.0-alpha](https://github.com/dadrus/heimdall/compare/v0.12.0-alpha...v0.13.0-alpha) (2024-01-03)


### ⚠ BREAKING CHANGES

* Endpoint specific HTTP cache settings refactored to allow HTTP cache ttl definition ([#1043](https://github.com/dadrus/heimdall/issues/1043))

### Features

* OAuth2/OIDC metadata discovery for `jwt` authenticator ([#1043](https://github.com/dadrus/heimdall/issues/1043)) by @martin31821 ([2dbfa5f](https://github.com/dadrus/heimdall/commit/2dbfa5f49bf7611e41992d6946fe77a34cd237d3))
* OAuth2/OIDC metadata discovery for `oauth2_introspection` authenticator ([#1043](https://github.com/dadrus/heimdall/issues/1043)) by @martin31821 ([2dbfa5f](https://github.com/dadrus/heimdall/commit/2dbfa5f49bf7611e41992d6946fe77a34cd237d3))


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
* Proxy buffer sizes example fixed ([#814](https://github.com/dadrus/heimdall/issues/814)) by @vinerich ([6867822](https://github.com/dadrus/heimdall/commit/68678228af37e21e11273cbdc88f5326494ef8c5))

## [0.10.1-alpha](https://github.com/dadrus/heimdall/compare/v0.10.0-alpha...v0.10.1-alpha) (2023-06-28)


### Bug Fixes

* Allow url rewrites with only a subset of fields set (proxy mode) ([#742](https://github.com/dadrus/heimdall/issues/742)) by @netthier ([109365f](https://github.com/dadrus/heimdall/commit/109365f7f4fecabfd7ee5abb112f0338af23ce13))
* Include fullname in Helm RBAC resource names ([#737](https://github.com/dadrus/heimdall/issues/737)) by @netthier ([dff3d4d](https://github.com/dadrus/heimdall/commit/dff3d4da3ef2baf46ee3064a88dd4984a7fdbb74))
* Working `authClassName` filter if multiple heimdall deployments are present in a cluster ([#742](https://github.com/dadrus/heimdall/issues/742)) by @netthier ([109365f](https://github.com/dadrus/heimdall/commit/109365f7f4fecabfd7ee5abb112f0338af23ce13))

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
