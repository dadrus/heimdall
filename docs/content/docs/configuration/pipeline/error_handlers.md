---
title: "Error Handlers"
date: 2022-06-09T18:57:29+02:00
lastmod: 2022-06-09T18:57:29+02:00
draft: true
toc: true
menu:
  docs:
    weight: 50
    parent: "Pipeline"
---

Error Handlers are responsible for execution of logic if any of the handlers [authenticators]({{< ref "authenticators.md" >}}), [authorizers]({{< ref "authorizers.md" >}}), [hydrators]({{< ref "hydrators.md" >}}) or [mutators]({{< ref "mutators.md" >}}) fail. The error handlers range from a simple error response to the client which sent the request to sophisticated handlers supporting complex logic and redirects. 

The following section describes the available error handler types in more detail.

## Error Handler Types

### Default

This error handler is always there and is executed if no other error handler is responsible for the handling of an error. Actually, there is no need to explicitly configure it. The only exception is to allow overriding the [default rule]({{< ref "../rules/_index.md#default-rule" >}})'s error handler chain in a rule for performance reasons (if configured error handlers in the default rule should not be considered). This error handler type doesn't have any configuration options.

To enable the usage of this error handler, you have to set the `type` property to `default`.

**Example**

```yaml
id: foo
type: default
```

### Redirect

This error handler allows to redirect the client to another endpoint, e.g. to let the user authenticate. Technically this error handler returns e.g. a HTTP `302 Found` response code and sets the HTTP `Location` header.

To enable the usage of this hydrator, you have to set the `type` property to `redirect`.

Configuration using the `config` property is mandatory. Following properties are available:

| Name                        | Type                                                                                          | Mandatory | Overridable | Description                                                                                                                                                                                                                |
|-----------------------------|-----------------------------------------------------------------------------------------------|-----------|-------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `to`                        | *URL*                                                                                         | yes       | no          | The url to redirect the client to. If no `return_to_query_parameter` is defined, the value of the HTTP `Location` hader is set to the configured value.                                                                    |
| `return_to_query_parameter` | *string*                                                                                      | no        | no          | If you want to return the user back to the url, Heimdall was handling when this error handler kicked in and your authentication system supports this by considering a specific query parameter, you can configure it here. |
| `code`                      | *int*                                                                                         | no        | no          | The code to be used for the redirect. Defaults to `302 Found`. Heimdall does not check the configured code for HTTP redirect validity!                                                                                     |
| `when`                      | *[ErrorConditionMatcher]({{< ref "configuration_types.md#error-condition-matcher" >}}) array* | yes       | yes         | Conditions, which must hold true for this error handler to execute.                                                                                                                                                        |

**Example**

The redirect error handler below is configured to kick in for web requests (HTTP `Accept` header contains `text/html`) if an `unauthorized` error occurred (an error raised by authenticators). In this case, it will redirect the client (for web requests, usually a browser) to `http://127.0.0.1:4433/self-service/login/browser` and also add the `return_to` query parameter with the current url to the redirect url.

So, e.g. if Heimdall was handling the request for `http://my-service.local/foo`, the value of the HTTP `Location` header will be set to `http://127.0.0.1:4433/self-service/login/browser?return_to=http%3A%2F%2Fmy-service.local%2Ffoo`

```yaml
id: authenticate_with_kratos
type: redirect
config:
  to: http://127.0.0.1:4433/self-service/login/browser
  return_to_query_parameter: return_to
  when:
    - error:
        - unauthorized
      request_headers:
        Accept:
          - text/html
```


### WWW-Authenticate

This error handler responds with HTTP `401 Unauthorized` and a `WWW-Authenticate` HTTP header set. As of now, this error handler is the only one error handler, which transforms Heimdall into an authentication system, a very simple one though ;). By configuring this error handler you can implement the [Basic HTTP Authentication Scheme](https://datatracker.ietf.org/doc/html/rfc7617) by also making use of the [Basic Auth]({{< ref "authenticators.md#basic-auth" >}}) authenticator. Without that authenticator, the usage of this error handler does actually not make any sense.

To enable the usage of this hydrator, you have to set the `type` property to `www_authenticate`.

Configuration using the `config` property is mandatory. Following properties are available:

| Name    | Type                                                                                            | Mandatory | Overridable | Description                                                                                                                                     |
|---------|-------------------------------------------------------------------------------------------------|-----------|-------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| `realm` | *string*                                                                                        | no        | yes         | The "realm" according to [RFC 7235, section 2.2](https://datatracker.ietf.org/doc/html/rfc7235#section-2.2). Defaults to "Please authenticate". |
| `when`  | **[ErrorConditionMatcher]({{< ref "configuration_types.md#error-condition-matcher" >}}) array** | yes       | yes         | Conditions, which must hold true for this error handler to execute.                                                                             |

**Example**

The www authenticate error handler below is configured to kick in for web requests (HTTP `Accept` header contains `text/html`) if an `unauthorized` error occurred (an error raised by authenticators). In this case, it will respond with HTTP `401 Unauthorized` and a `WWW-Authenticate` header set to `Basic realm="My fancy app"`.

```yaml
id: basic_authenticate
type: www_authenticate
config:
  realm: "My fancy app"
  when:
    - error:
        - unauthorized
      request_headers:
        Accept:
          - text/html
```