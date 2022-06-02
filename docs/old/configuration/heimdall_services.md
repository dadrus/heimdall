---
layout: default
title: Heimdall Services
parent: Configuration
---

# Heimdall Services
{: .no_toc }

Heimdall can be operated in two modes - as a Reverse Proxy, or as a Decision API. Both modes have specific configurations, and configuration which they have in common. All of these are documented below.

## Table of contents
{: .no_toc .text-delta }

1. TOC
   {:toc}

---

## Decision API
The configuration for the Decision API service is optional and can be done either via environment variables or in a config file 

```yaml
serve:
  api:
    host: 0.0.0.0
    port: 4456
    verbose_errors: true
    timeout:
      read: 1s
      write: 1s
      idle: 1s
    cors:
      # defines a list of origins that may access the resource. Defaults to accept all origins.
      allowed_origins: []
      # defines a list methods allowed when accessing the resource. Used in response to a preflight request. Defaults to [GET,POST,HEAD,PUT,DELETE,PATCH]
      allowed_methods: []
      # defines a list of request headers that can be used when making the actual request. This is in response to a preflight request. Default value is an empty list
      allowed_headers: []
      # defines a whitelist headers that clients are allowed to access. Defaults to an empty list
      exposed_headers: []
      # indicates whether the response to the request can be exposed when the credentials flag is true. When used as part of a response to a preflight request, this indicates whether the actual request can be made using credentials. Defaults to 'false'
      allow_credentials: false
      max_age: 1s
    trusted_proxies: []
    tls:
       key: foo
       cert: bar
```

## Reverse Proxy

## Signer

## Logging

## Tracing

## Monitoring