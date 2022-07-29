# Heimdall

## Background

Heimdall is inspired by the ZeroTrust idea and also by [Ory's OAthkeeper](https://www.ory.sh/docs/oathkeeper). Some experience with the latter and my inability to update it to include the desired functionality and behavior was Heimdall's born hour.

## Heimdall's Promise

Heimdall authenticates and authorizes incoming HTTP requests as well as enriches these with further contextual information and finally transforms resulting subject information into a format, required by the upstream services. And all of that can be controlled by each and every backend service individually.

It is supposed to be used either as
* a **Reverse Proxy** (not yet implemented) in front of your upstream API or web server that rejects unauthorized requests and forwards authorized ones to your end points, or as
* a **Decision API**, which integrates with your API Gateway (Kong, NGNIX, Envoy, Traefik, etc) and then acts as a Policy Decision Point.

## Example Usage

Create a configuration file:

```yaml
# heimdall.yaml

log:
  level: info

pipeline:
  authenticators:
    - id: anonymous_authenticator
      type: anonymous
  mutators:
    - id: create_jwt
      type: jwt

rules:
  default:
    methods:
      - GET
      - POST
    execute:
      - authenticator: anonymous_authenticator
      - mutator: create_jwt
```

Start heimdall (here in the decision operation mode):

```bash
docker run -t -p 4456:4456 -v $PWD:/heimdall/conf \
  dadrus/heimdall:latest serve api -c /heimdall/conf/heimdall.yaml
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
< HTTP/1.1 202 Accepted
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
* Heimdall answered with an HTTP `202 Accepted` response and set the expected `Authorization` header, which the API-Gateway would forward to the upstream service together with the original request.

## Reference

* [Documentation](https://dadrus.github.io/heimdall/docs/welcome/) - Checkout the documentation for more details.
* [GitHub](https://github.com/dadrus/heimdall) - Visit heimdall on GitHub.

## Image Variants

As of today heimdall is built as a multi-platform image for the following platforms:

* linux/amd64
* linux/arm64
* linux/arm

If you need support for other platforms, don't hesitate to file an issue at GitHub. Contributions are very welcome as well!

All images adhere to the `dadrus/heimdall:<version>` pattern, with `dadrus/heimdall:latest` referencing the latest version as well.

## License

Heimdall is licensed under [Apache-2.0](https://github.com/dadrus/heimdall/blob/main/LICENSE) license.