---
title: "From_source"
date: 2022-06-09T15:54:18+02:00
lastmod: 2022-06-09T15:54:18+02:00
description: ""
lead: ""
draft: true
images: []
weight: 999
toc: true
---

# Install from Source

This document covers how to build heimdall from its source code as well as how to run heimdall using a minimum configuration. If you want to try out a scenario close to real-life, head over to [Quick Start]({{ site.baseurl }}{% link install/quick_start.md %}) chapter.

## Prerequisites

* [git](https://git-scm.com/)
* The [Go](https://go.dev/dl/) programming language >= 1.18.1
* [Docker](https://docs.docker.com/install/) if you want to build a docker container (you don't need Golang then)

## Download
Retrieve the latest copy of heimdall source code by cloning the git repository

```bash
$ git clone git@github.com:dadrus/heimdall.git
```

## Build with go
Build using a single line with `go build`

```bash
$ go build -trimpath -ldflags="-buildid= -w -s -X heimdall/cmd.Version=my-custom-build"
```

The flags are set by intention. Using `-trimpath` and `-buildid=` as part of the `-ldflags` argument ensures the build is reproducible (See also [Reproducible Builds](https://reproducible-builds.org/)). Other flags remove unused symbols and debug information.

## Build with Docker
The Docker build uses exactly the same `go build` command from above, compresses the binary and ensures the resulting docker image is secure.

```bach
$ docker build -t heimdal:local ./docker/Dockerfile .
```

The Dockerfile builds the heimdall image for linux with amd64 architecture.

## Configure

heimdall can be configured via environment variables, as well as using a configuration file. For simplicity reasons, we'll use a configuration file here. So create a config file (`config.yaml`) with the following content:

```yaml
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

This configuration will create a JSON Web Token (JWT) with `sub` claim set to `anonymous` for every request on every URL for the HTTP methods GET and POST. The JWT itself will be put into the `Authorization` header as a bearer token.

## Run
Finally, run heimdall specifying the configuration file from above

If you've built heimdall using `go build`, just execute

```bash
$ ./heimdall serve api -c config.yaml
```

The above command will start heimdall in a decision api mode. By default, the service will be served on port `4456`.

Otherwise, if you've built a Docker image, run heimdall in the decision api mode it via

```bash
$ docker run -t -v $PWD:/heimdall/conf -p 4456:4456 \
  heimdal:local serve api -c /heimdall/conf/config.yaml
```

In both cases, you'll see similar output to

```
8:16PM WRN Could not initialize opentracing tracer. Tracing will be disabled. error="no 
supported/configured opentracing provider"
8:16PM INF Loading pipeline definitions
8:16PM ERR Failed to load rule definitions provider: file_system error="invalid provider 
configuration"
8:16PM WRN Key store is not configured. NEVER DO IT IN PRODUCTION!!!! Generating an RSA 
key pair.
8:16PM WRN No key id for signer configured. Taking first entry from the key store
8:16PM INF Starting cache evictor
8:16PM INF Starting rule definition loader
8:16PM INF Prometheus endpoint starts listening on: :9000
8:16PM INF Decision API endpoint starts listening on: :4456
```

Ignore the error. It is expected as we've not configured any rule set. Nevertheless, the default rule can be used.

## Use

Sent some request to heimdall's decision endpoint:

```bash
$ curl -v 127.0.0.1:4456/decisions/foobar
```

Here, we're asking to apply the default rule for the `foobar` path using the `GET` HTTP verb.

On completion, you should see the `Authorization` header in the response, like in the output below:

```bash
*   Trying 127.0.0.1:4456...
* Connected to 127.0.0.1 (127.0.0.1) port 4456 (#0)
> GET /decisions/foobar HTTP/1.1
> Host: 127.0.0.1:4456
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: Heimdall Decision API
< Date: Wed, 27 Apr 2022 18:16:19 GMT
< Content-Type: text/plain; charset=utf-8
< Content-Length: 2
< Authorization: Bearer eyJhbGciOiJQUzI1NiIsImtpZCI6ImU5NmZmYmMyLTlkMGItNmU3Ni0wZGE1LWVhMGNhZmNjMz
BhOSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NTEwODQyNzksImlhdCI6MTY1MTA4MzM3OSwiaXNzIjoiaGVpbWRhbGwiLCJqdGk
iOiJkN2I5OGIzMy05NWIyLTRmMjgtOWE3NS1mZmUxMzJlMzYzYTciLCJuYmYiOjE2NTEwODMzNzksInN1YiI6ImFub255bW91c
yJ9.merxkl1pcexeFS73tGWUfmOJoyIK1390gnaaiJ3ajtHVsvnvuo9xYPlAQvRnEdeXN-J439nI426Cin9KZF8JJYETgG7KtU
qo_n5dkLrsokdi-STv609QQ-2rVmqjSnf9kd7e0ww5Qh0p-WSEbKkLng-sVmBUQ3Dg-qyAJ9YA5f_qgCPRuO5tgRVPRX-NHwKy
cA28BnKwmHUPOmjuwBD7PeL3m_yOQEJgWhjGeIY_zkYE6F637JVS9QdesM-fOoPXeDXziOHtzMzy6QclhwofQn4FjgkF7FGIbH
BamFj_xtTMUonvqjPXu8KYp39GXXnpIlEv2jdQ5u2C0gmuIpsBIw
< 
* Connection #0 to host 127.0.0.1 left intact
```