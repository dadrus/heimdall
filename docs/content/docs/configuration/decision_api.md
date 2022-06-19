---
title: "Decision API"
date: 2022-06-09T18:55:36+02:00
lastmod: 2022-06-09T18:55:36+02:00
draft: true
toc: true
menu: 
  docs:
    weight: 10
    parent: "Configuration"
---

Decision API is one of the operating modes supported by Heimdall, used if you start Heimdall with `heimdall serve api`. By default, Heimdall listens on `0.0.0.0:4456/decisions` endpoint for incoming requests in this mode of operation and also configures useful default timeouts. No other options are configured. You can, and should however adjust the configuration for your needs.

## Configuration

The configuration for the Decision API can be adjusted in the `api` property of heimdall's configuration and supports following properties.

### Host

By making use of the `host` (*string*) property, you can specify the TCP/IP address on which heimdall should listen for connections from client applications. The entry `0.0.0.0` allows listening for all IPv4 addresses. `0.0.0.0` is also the default setting.

**Example**

In this example, we configure heimdall to allow only local TCP/IP “loopback” connections to be made. Makes actually only sense, if your reverse proxy/gateway, which communicates with Heimdall, runs on the same machine.

```yaml
api:
  host: 127.0.0.1
```

### Port

By making use of the `port` (*integer*) property, you can specify the TCP port the heimdall should listen on. Defaults to `4456`.

**Example**

In this example, we configure heimdall to listen on port `4444` for Decision API requests.

```yaml
api:
  port: 4444
```

### Verbose Errors

By making use of `verbose_errors` (*boolean*) you can instruct Heimdall's default error handler to preserve error information and provide it in the response body to the caller. Defaults to `false`.

Heimdall supports MIME type negotiation. So, if your reverse proxy/gateway sets the HTTP `Accept` header to e.g. `application/json`, and Heimdall run into an unhandled internal error condition, in addition to responding with `500 Internal Server Error`, it will render an error message, like shown below, if `verbose_errors` has been set to `true`.

```json
{
  "code": "internalServerError",
  "message": "whatever led to the error"
}
```

The `message` will however contain just high-level information, like "failed to parse something", but will not contain any stack traces.

**Example**

```yaml
api:
  verbose_errors: true
```

### Timeout

Like written above, Heimdall configures useful timeout defaults. You can however override this by making use of the `timeout` option and specifying the timeouts, you need. Following configuration options are supported:

| Name    | Type                                     | Description                                                                                                                                                       |
|---------|------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `read`  | *[Duration]({{< relref "#duration" >}})* | The amount of time allowed to read the full request including body. Defaults to 5 seconds.                                                                        |
| `write` | *[Duration]({{< relref "#duration" >}})* | The maximum duration before timing out writes of the response. Defaults to 10 seconds                                                                             |
| `idle`  | *[Duration]({{< relref "#duration" >}})* | The maximum amount of time to wait for the next request when keep-alive is enabled. If `ìdle` is `0`, the value of `read` timeout is used. Defaults to 2 minutes. |

**Example**

In this example, we are setting the read timeout to 1 second, write timeout to 2 seconds and the idle timeout to 1 minute.

```yaml
api:
  timeout:
    read: 1s
    write: 2s
    idle: 1m
```

### CORS

[CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) (Cross-Origin Resource Sharing) headers can be added and configured by making use of the `cors` option. This functionality allows for advanced security features to quickly be set. If CORS headers are set, then the Heimdall does not pass preflight requests to its decision pipeline, instead the response will be generated and sent back to the client directly. Following configuration options are supported:

| Name                | Type                                     | Description                                                                                                                                                                                                                                                                                                                      |
|---------------------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `allowed_origins`   | *string array*                           | List of origins that may access the resource. Defaults to all, if not set, but any of the other CORS options are configured.                                                                                                                                                                                                     |
| `allowed_methods`   | *string array*                           | List of methods allowed when accessing the resource. This is used in response to a preflight request. Defaults to `GET`, `POST`, `HEAD`, `PUT`, `DELETE`, `PATCH` if not set, but any of the other CORS options are configured.                                                                                                  |
| `allowed_headers`   | *string array*                           | List of request headers that can be used when making the actual request.                                                                                                                                                                                                                                                         |
| `exposed_headers`   | *string array*                           | "Allow-List" of headers that clients are allowed to access.                                                                                                                                                                                                                                                                      |
| `allow_credentials` | *boolean*                                | Indicates whether or not the response to the request can be exposed when the credentials flag is true. When used as part of a response to a preflight request, this indicates whether or not the actual request can be made using credentials. Defaults to `false` if not set, but any of the other CORS options are configured. |
| `max_age`           | *[Duration]({{< relref "#duration" >}})* | Indicates how long the results of a preflight request can be cached. Defaults to 0 seconds if not set, but any of the other CORS options are configured.                                                                                                                                                                         |

**Example**

```yaml
api:
  cors:
    allowed_origins:
      - example.org
    allowed_methods:
      - HEAD
      - PATCH
    allow_credentials: true
    max_age: 10s
```

### TLS

By default, the Decision API accepts HTTP requests. Depending on your deployment scenario, you could require Heimdall to accept HTTPS requests only. You can do so by making use of the `tls` option. 

As of today, the available configuration options are however limited to setting up the private key, as well as the corresponding certificate. TLSv1.2 and TLSv1.3 can however be used by the Decision API client. TLSv1.2 cipher spec usage is however limited to what the Go Language supports.

| Name   | Type     | Description                                                                                                                                                  |
|--------|----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `key`  | *string* | Path to the private key in PEM format. PKCS#1, as well as PKCS#8 formats are supported.                                                                      |
| `cert` | *string* | Path to the certificate in PEM format. The certificate file may contain intermediate certificates following the leaf certificate to form a certificate chain |

**Example**

```yaml
api:
  tls:
    key: /path/to/private_key.pem
    cert: /path/to/certificate.pem
```

### Trusted Proxies

The usage of the Decision API makes only sense, if operated behind some sort of proxy, like API Gateway, etc. In such cases certain header information may be sent to Heimdall using special `X-Forwarded-*` headers or the [Forwarded](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded) header. For example, the `Host` HTTP header is usually used to return the requested host. But when you’re behind a proxy, the actual host may be stored in an `X-Forwarded-Host` header, which could, however, also be spoofed.

To prevent header spoofing and allowing such headers to be accepted from trusted proxies only (so the systems, you have configured to make use of Heimdall's Decision API), you should configure the `trusted_proxies` (*string array*) option and list the IPs, or IP ranges (CIDR notation) of your proxies, which make use of Heimdall's Decision API. If not configured, Heimdall will accept those headers from any client.

If you configure `trusted_proxies` to an empty list, Heimdall will not make use of any headers that could be spoofed. This would usually be the configuration for proxies, which do not send information about the client request in headers, but use the corresponding HTTP scheme, method, path, etc, while communicating with Heimdall (e.g. Nginx). If you put Heimdall behind e.g. Traefik, which forwards this information in `X-Forwarded-*` headers, you should configure the `trusted_proxies` list to contain the addresses of your Traefik instances only.

**Example 1**

Disable usage of any headers, which could be spoofed for all clients

```yaml
api:
  trusted_proxies: []
```

**Example 2**

Disable usage of any headers, which could be spoofed for all clients, except those listed in the configuration.

```yaml
api:
  trusted_proxies:
    - 192.168.2.15
    - 192.168.2.16 
```

**Example 3**

Disable usage of any headers, which could be spoofed for all clients, except those which are within the configured IP range.

```yaml
api:
  trusted_proxies:
    - 192.168.2.0/24
```
