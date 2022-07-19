# Changelog

## [0.1.0-alpha](https://github.com/dadrus/heimdall/compare/v0.0.1-alpha...v0.1.0-alpha) (2022-07-19)


### Features

* **docs:** bottom navigation links added ([59b423d](https://github.com/dadrus/heimdall/commit/59b423dec9b080d1bd03903d5b401dc7718b7811))
* Enables usage of heimdall context in specific templates and made template and script compiling on load and not on execute ([#68](https://github.com/dadrus/heimdall/issues/68)) ([42b59f3](https://github.com/dadrus/heimdall/commit/42b59f39e784faae28f5b2f1511cbd35ade9e131))
* health command implemented - makes use of the new health endpoint ([86cad54](https://github.com/dadrus/heimdall/commit/86cad54ddf5280513e03c15daca4b7cd50b1845a))
* Health endpoint ([#69](https://github.com/dadrus/heimdall/issues/69)) ([5d2241e](https://github.com/dadrus/heimdall/commit/5d2241ea6e14790344a2f883f50ee5292b1dc4f8))
* initial Justfile to not to have to remeber the params while building Docker image or the heimdall binary ([aa3cea2](https://github.com/dadrus/heimdall/commit/aa3cea24d77876ce0d8a460c6b0a057b819f3a7a))
* jwks endpoint implementation & some refactorings related to it ([#71](https://github.com/dadrus/heimdall/issues/71)) ([a16ce7e](https://github.com/dadrus/heimdall/commit/a16ce7ec01b2613dc7bb3a65901e57589fb4e32a))
* lint command added ([b2fb7a6](https://github.com/dadrus/heimdall/commit/b2fb7a6a4d0ed705b9e138110b47be6835f4f8a5))


### Bug Fixes

* auth strategy is not always set ([bbeffc2](https://github.com/dadrus/heimdall/commit/bbeffc24bc7a1ef9bd5c5e3b9ba3b742e61a3bd8))
* authenticator fallback happens now only if the authentication data expected by a failed authenticator is not present. ([#31](https://github.com/dadrus/heimdall/issues/31)) ([3338463](https://github.com/dadrus/heimdall/commit/3338463c757898b3927c93d4b3ccd63910fe00a4))
* cache key calculation for remote authorizer and hydrator without payload ([fec9179](https://github.com/dadrus/heimdall/commit/fec917988e628071975cb122a71028a92d702ce6))
* ci and security badges ([5ebe830](https://github.com/dadrus/heimdall/commit/5ebe830b6d863e20349dd50ae7d81e63de9aa671))
* config debug output removed ([6c24e46](https://github.com/dadrus/heimdall/commit/6c24e46ef571c852ecdf696703bc5b02908035ee))
* config loading with heimdall specific configuration structs & corresponding test ([1ddbedb](https://github.com/dadrus/heimdall/commit/1ddbedb2224ad91ecd7f2fcbabb748db0b9e981f))
* Dockerfile fixed to properly reference the Version variable ([cd1ade9](https://github.com/dadrus/heimdall/commit/cd1ade9317de8c2a06674d613044777d95aa710c))
* **docs:** crossreferences fixed ([688bc2a](https://github.com/dadrus/heimdall/commit/688bc2a42bf02308ddb2625fc1d261e7b346d3f7))
* **docs:** gh-pages pipeline updated to install mermaid ([465b0d2](https://github.com/dadrus/heimdall/commit/465b0d2cc99d3c1423c7910d49f87de5cc2ea738))
* **docs:** links fixed, bottom navigation made smaller ([77f2be0](https://github.com/dadrus/heimdall/commit/77f2be074ebe54a45aefa2885f772de6862fedb3))
* **docs:** next attempt to fix mermaid installation ([ab08d9f](https://github.com/dadrus/heimdall/commit/ab08d9f6fc2de8a60708c1cad5e9f0f2bc275dd6))
* **docs:** set draft to false and fixed some example blocs ([a1bb803](https://github.com/dadrus/heimdall/commit/a1bb80378f3b9d2ffdef88f04b67d0e669130a1e))
* **docs:** setting log format example ([06f2282](https://github.com/dadrus/heimdall/commit/06f2282f845f3f02caebd90f2398c03165c6c19b))
* hopefully the links are fixed now. Relates to [#44](https://github.com/dadrus/heimdall/issues/44) ([67ab999](https://github.com/dadrus/heimdall/commit/67ab999827cc8f6b846892fc598c8bee1eba7d4c))
* imports organized ([8385988](https://github.com/dadrus/heimdall/commit/83859887b695b0d9e074bb48810ba614746e244d))
* making overwriting of JWT specific claims, set by the JWT signer not possible ([#48](https://github.com/dadrus/heimdall/issues/48)) ([22a986f](https://github.com/dadrus/heimdall/commit/22a986f1b28ad3ddf839f97906d78c28576021a4))
* next attempt to fix [#44](https://github.com/dadrus/heimdall/issues/44) ([76ede7c](https://github.com/dadrus/heimdall/commit/76ede7c5998c673a309574aaa814ebdd60c701f9))
* next attempt to fix [#44](https://github.com/dadrus/heimdall/issues/44). Absolute URLs changed to relative ones ([35b775b](https://github.com/dadrus/heimdall/commit/35b775be523c9786c308ae41407bfe67624d5781))
* next attempt to fix [#44](https://github.com/dadrus/heimdall/issues/44). Absolute URLs changed to relative ones ([a1abbe2](https://github.com/dadrus/heimdall/commit/a1abbe23e6fb4b9919df60de64a67355485a80a6))
* removed useless description. Provided anyway by cobra ([12d2360](https://github.com/dadrus/heimdall/commit/12d2360d8838a59472b0724a4b19e5d83097ae57))
* schema adjusted to reflect the expected configuration ([400eb2e](https://github.com/dadrus/heimdall/commit/400eb2e18e3bf591f11429b355fc2517690f9b37))
* test config updated to reflect recent template implementation updates ([56a544f](https://github.com/dadrus/heimdall/commit/56a544fcbeafe9b89fba8a38684650b0059fb8f4))
