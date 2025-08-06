# Heimdall

## Background

Heimdall is inspired by the ZeroTrust idea and tries to adopt it to some extent to web applications.

## Heimdall's Promise

Heimdall authenticates and authorizes incoming HTTP requests as well as enriches these with further contextual information and finally transforms resulting subject information into a format, required by the upstream services. And all of that can be controlled by each and every backend service individually.

It is supposed to be used either as
* a **Reverse Proxy** in front of your upstream API or web server that rejects unauthorized requests and forwards authorized ones to your end points, or as
* a **Decision Service**, which integrates with your API Gateway (Kong, NGNIX, Envoy, Traefik, etc.) and then acts as a Policy Decision Point.

## Reference

* [Documentation](https://dadrus.github.io/heimdall/) - Checkout the documentation for more details.
* [GitHub](https://github.com/dadrus/heimdall) - Visit heimdall on GitHub.

## Image Variants

As of today heimdall is built as a multi-platform image for the following platforms:

* linux/amd64
* linux/arm64
* linux/arm/v7

If you need support for other platforms, don't hesitate to file an issue at GitHub. Contributions are very welcome as well!

All images adhere to the following patterns:

* For stable, respectively released versions, image tags have the suffix of the corresponding version and have the `dadrus/heimdall:<version>` form. E.g. an image tagged with `dadrus/heimdall:0.16.8` is the image for the released `0.16.8` version of heimdall. In addition, there is a `dadrus/heimdall:latest` tag referencing the latest released version as well.

* Development images are created from the main branch by heimdall's continuous integration and are tagged with the `dev` and with the `dev-<SHA>` suffix, where the SHA is the commit in heimdall main from which it was created. For example, after a build at commit `730b2206`, an image will be created for `dadrus/heimdall:dev-730b2206fdfc688ca42bcdf0e344d8fa6bfba232` and the image `dadrus/heimdall:dev` will be tagged to it until the next build.

Each published image is signed using [Cosign](https://docs.sigstore.dev/docs/signing/quickstart/). The signatures are located in the same repository and have the tag pattern `sha256-<SHA256>.sig`. An SBOM is attached to each image as an attestation, created via Cosign as well. These objects are also present in this repository with tags adhering to the `sha256-<SHA256>.att` name pattern. Both, the images and the SBOM attestations are signed using [keyless signing feature](https://docs.sigstore.dev/docs/signing/overview/). Please refer to heimdall's [Documentation](https://dadrus.github.io/heimdall/dev/docs/operations/security/#_verifying_heimdall_binaries_and_container_images) on how to verify both and extract the SBOM.

## License

Heimdall is licensed under [Apache-2.0](https://github.com/dadrus/heimdall/blob/main/LICENSE) license.