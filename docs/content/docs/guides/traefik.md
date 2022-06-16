---
title: "Traefik Proxy Integration"
date: 2022-06-09T18:59:49+02:00
lastmod: 2022-06-09T18:59:49+02:00
description: ""
lead: ""
draft: true
images: []
weight: 999
toc: true
menu:
  docs:
    parent: "Guides"
---

[Traefik Proxy](https://doc.traefik.io/traefik/) is modern HTTP proxy and load balancer for microservices, heimdall can be integrated with via the [ForwardAuth Middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) by making use of the available [Decision API]({{ site.baseurl }}{% link index.md %}).

To achieve this,

* configure traefik
  * to make use of the aforesaid ForwardAuth middleware by setting the address property to the decision api endpoint and
  * by including the required header name(s), heimdall sets in the HTTP responses into the authResponseHeaders property.
* configure the route of your service to make use of this middleware

Example (using Docker labels):

```yaml
edge-router:
  image: traefik
  # further configuration
  labels:
    - traefik.http.middlewares.heimdall.forwardauth.address=http://heimdall:4456/decisions
    - traefik.http.middlewares.heimdall.forwardauth.authResponseHeaders=X-Id-Token,Authorization
    # further labels

service:
  image: my-service
  # further configuration
  labels:
    - traefik.http.routers.service.middlewares=heimdall
    # further labels
```