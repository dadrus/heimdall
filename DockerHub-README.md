# Heimdall

## Background

Heimdall is inspired by the ZeroTrust idea and tries to adopt it to some extent to web applications.

## Heimdall's Promise

Heimdall authenticates and authorizes incoming HTTP requests as well as enriches these with further contextual information and finally transforms resulting subject information into a format, required by the upstream services. And all of that can be controlled by each and every backend service individually.

It is supposed to be used either as
* a **Reverse Proxy** in front of your upstream API or web server that rejects unauthorized requests and forwards authorized ones to your end points, or as
* a **Decision Service**, which integrates with your API Gateway (Kong, NGNIX, Envoy, Traefik, etc.) and then acts as a Policy Decision Point.

## Run heimdall in Decision operation mode

Create a configuration file named `heimdall.yaml`:

```yaml
log:
  level: info

mechanisms:
  authenticators:
  - id: anonymous_authenticator
    type: anonymous
  finalizers:
  - id: create_jwt
    type: jwt

default_rule:
  methods:
  - GET
  - POST
  execute:
  - authenticator: anonymous_authenticator
  - finalizer: create_jwt
```

Start heimdall:

```bash
docker run -t -p 4456:4456 -v $PWD:/heimdall/conf \
  dadrus/heimdall:latest serve decision -c /heimdall/conf/heimdall.yaml
```

Call the decision service endpoint to emulate behavior of an API-Gateway:

```bash
curl -v 127.0.0.1:4456/foobar
```

You should now see similar output to the following snippet:

```bash
*   Trying 127.0.0.1:4456...
* Connected to 127.0.0.1 (127.0.0.1) port 4456 (#0)
> GET /foobar HTTP/1.1
> Host: 127.0.0.1:4456
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: Heimdall Decision API
< Date: Sat, 25 Jun 2022 14:10:16 GMT
< Content-Length: 0
< Authorization: Bearer eyJhbGciOiJQUzI1NiIsImtpZCI6IjJkZGIxZDM3MWU1MGFjNDQ5ZGJhNjcyNj
ZmZDRjMzU0OWZjNmRmYTYiLCJ0eXAiOiJKV1QifQeyJleHAiOjE2NTYxNjY1MTYsImlhdCI6MTY1NjE2NjIxNi
wiaXNzIjoiaGVpbWRhbGwiLCJqdGkiOiIxYjdlODdjYi0zYjdjLTQ1ZDAtYWEyZi00MTRhYmI2YjBlMzciLCJu
YmYiOjE2NTYxNjYyMTYsInN1YiI6ImFub255bW91cyJ9MY6fjk7K6ZNn57Mrjy6UGI1cvIMCOOEJoCQF45PHQ3
4BfoPxMuTRjdVUZPX4xnT4suyWySsaU1wisgXv4CuMf4WsEUCPKOH8NKv5Zty6eXjTdWQpekDWYsHpVVwz8UHL
mrRASlo_JKErj64wPbRcQWyLMR9X-4cR28ZuH3IbyXh4-XlGNEMAVWYFaZGv1QlEd7jcw3jSVK0b5AtY-NUcVQ
lccWpqWD43AE-3spchqboFuiuW5IxFGd4Mc0Dp6uepuQ-XiWEFg9rxnaxl-Grr3LfSY83oML53Akrl4lGtVBu5
5QVVjduv_b2ykRnqh7Im9lSivokuVMEuSE8bN2qnqg
<
* Connection #0 to host 127.0.0.1 left intact
```

What did you actually do? ;)

* You've created a very simple configuration with a default rule, which instructs heimdall to create a JSON Web Token (JWT) with the 'sub' claim set to 'anonymous' for every request on every URL for the HTTP methods GET and POST. You've seen the resulting JWT in the snipped above.
* You've started heimdall in the decision operation mode
* And sent an HTTP GET request to an imaginary `foobar` endpoint. This is also what an API-Gateway will do before forwarding the received request to an upstream's `foobar` endpoint.
* Heimdall answered with an HTTP `200 OK` response and set the expected `Authorization` header, which the API-Gateway would forward to the upstream service together with the original request.

## Run heimdall in Proxy operation mode

To run the following configuration, you need docker-compose. 

Create a config file (`config.yaml`) with the following content:
```yaml
log:
  level: info

mechanisms:
  authenticators:
  - id: anonymous_authenticator
    type: anonymous
  authorizers:
  - id: deny_all_requests
    type: deny
  - id: allow_all_requests
    type: allow
  finalizers:
  - id: create_jwt
    type: jwt
      
default_rule:
  execute:
  - authenticator: anonymous_authenticator
  - authorizer: deny_all_requests
  - finalizer: create_jwt

providers:
  file_system:
    src: /heimdall/conf/rule.yaml
    watch: true
```

Create a rule file (`rule.yaml`) with the following contents:

```yaml
version: "1alpha4"
rules:
  - id: test-rule
    match: 
      routes:
        - path: /**
    forward_to:
      host: upstream
    execute:
      - authorizer: allow_all_requests
```

Create a `docker-compose.yaml` file with the following contents and modify it to include the correct paths to your `config.yaml` and `rule.yaml` files:

```yaml
version: "3"

services:
  heimdall:
    image: dadrus/heimdall:latest
    volumes:
      # Mount your config file:
      - ./config.yaml:/heimdall/conf/config.yaml:ro
      # Mount your rule file:
      - ./rule.yaml:/heimdall/conf/rule.yaml:ro
    ports:
      - 4455:4455
    command: -c /heimdall/conf/config.yaml serve proxy
  
  upstream:
    image: containous/whoami:latest
```

Start the docker compose environment:

```bash
docker-compose up
```

Call the proxy service endpoint to emulate behavior of a client application:

```bash
curl -v 127.0.0.1:4455/foobar
```

You should now see similar output to the following snippet:

```bash
*   Trying 127.0.0.1:4455...
* Connected to 127.0.0.1 (127.0.0.1) port 4455 (#0)
> GET /foobar HTTP/1.1
> Host: 127.0.0.1:4455
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Thu, 04 Aug 2022 07:53:41 GMT
< Content-Type: text/plain; charset=utf-8
< Content-Length: 872
<
Hostname: 4f809f75f31b
IP: 127.0.0.1
IP: 172.22.0.3
RemoteAddr: 172.22.0.2:42100
GET /foobar HTTP/1.1
Host: upstream
User-Agent: curl/7.74.0
Accept: */*
Authorization: Bearer eyJhbGciOiJQUzI1NiIsImtpZCI6IjNhYjFiMDdmMmMyNjlkMWVlMTRjNzQ2NDA4
OTAyZjRlNWQ1MDAyOTgiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2NTkzMzczMjEsImlhdCI6MTY1OTMzNzAyMSw
iaXNzIjoiaGVpbWRhbGwiLCJqdGkiOiJjMmEzNjczMy04ZDBjLTQzYWQtOGFkNi0xM2Q4NGVhNDI1MTgiLCJuY
mYiOjE2NTkzMzcwMjEsInN1YiI6ImFub255bW91cyJ9.gw-h15LaUUYV-Sjk6Vf-kZflnZxn88lejVIIatKliv
FkeUz8oo9x9juKBSzr4nIVWjGZ_atGVmLoKshudHdnpvABx5cgBaz2_KDgifVzGORE1zld9vGDpU7IPjOyC9-M
b7vOOA1fq9pbQ4nfXw100AJJKFXSct9cYa3163kk_s-jEIPclhB0ZiPqGI-t_GiYJBCVKOTJPkkLKB51KCgn2y
PvO3qLCwO81JdCSFG9k2WLjWZlQe-a8u4El-2qctx8yB-vBFPIaQlwCJh66of3hcUs98IoVlMLGdTJSI4pX9nK
s8OMxVO37eI501gZXXkF5IiSsRAqV_o8pMcGZ47Ztg
Forwarded: for=172.22.0.1;proto=http
X-Forwarded-For: 172.22.0.1

* Connection #0 to host 127.0.0.1 left intact
```

What did you actually do? ;)

* You've created a very simple configuration with a default rule, with preconfigured defaults. The used authenticator instructs heimdall to create an anonymous subject for every request on every URL for the HTTP methods GET and POST. The default authenticator rejects any request and the default finalizer creates a JWT from the subject mentioned above.
* You've created a very simple rule, which reuses the default authenticator and finalizer and configures an authorizer, which allows any request to pass through.
* You've created and started a docker compose environment with heimdall operated in proxy mode and a "upstream" service, which responds with everything it receives.
* And sent an HTTP GET request to an imaginary `foobar` endpoint. 
* Heimdall run the request through its pipeline and forwarded the enriched (`Authorization` header) request to the "upstream" service, which just returned all it has received to the caller. 

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

* For stable, respectively released versions, image tags have the suffix of the corresponding version and have the `dadrus/heimdall:<version>` form. E.g. an image tagged with `dadrus/heimdall:0.11.1-alpha` is the image for the released `0.11.1-alpha` version of heimdall. In addition, there is a `dadrus/heimdall:latest` tag referencing the latest released version as well.

* Development images are created from the main branch by heimdall's continuous integration and are tagged with the `dev` and with the `dev-<SHA>` suffix, where the SHA is the commit in heimdall main from which it was created. For example, after a build at commit `730b2206`, an image will be created for `dadrus/heimdall:dev-730b2206fdfc688ca42bcdf0e344d8fa6bfba232` and the image `dadrus/heimdall:dev` will be tagged to it until the next build.

Each published image is signed using [Cosign](https://docs.sigstore.dev/docs/signing/quickstart/). The signatures are located in the same repository and have the tag pattern `sha256-<SHA256>.sig`. An SBOM is attached to each image as an attestation, created via Cosign as well. These objects are also present in this repository with tags adhering to the `sha256-<SHA256>.att` name pattern. Both, the images and the SBOM attestations are signed using [ keyless signing feature](https://docs.sigstore.dev/docs/signing/overview/). Please refer to heimdall's [Documentation](https://dadrus.github.io/heimdall/dev/docs/operations/security/#_verifying_heimdall_binaries_and_container_images) on how to verify both and extract the SBOM.

## License

Heimdall is licensed under [Apache-2.0](https://github.com/dadrus/heimdall/blob/main/LICENSE) license.