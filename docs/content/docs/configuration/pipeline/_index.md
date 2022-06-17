---
title: "Pipeline"
date: 2022-06-09T18:56:56+02:00
lastmod: 2022-06-09T18:56:56+02:00
draft: true
menu: 
  docs:
    weight: 60
    parent: "Configuration"
---

This section explains the available pipeline handler and mechanisms in detail. Before diving onto the details of these, we recommend to make yourself familiar with the principal architecture and components.

The general pipeline handlers are:

* [Authenticators]({{< ref "authenticators.md">}}) inspect HTTP requests, like the presence of a specific cookie, which represents the authentication object of the subject with the service and execute logic required to verify the authentication status and obtain information about that subject. A subject, could be a user who tries to use particular functionality of the upstream service, a machine (if you have machine-2-machine interaction), or something different. Authenticators ensure the subject has already been authenticated and the information available about it is valid.
* [Authorizers]({{< ref "authorizers.md">}}) ensure that the subject obtained via an authenticator step has the required permissions to submit the given HTTP request and thus to execute the corresponding logic in the upstream service. E.g. a specific endpoint of the upstream service might only be accessible to a "user" from the "admin" group, or to an HTTP request if a specific HTTP header is set.
* [Hydrators]({{< ref "hydrators.md">}}) enrich the information about the subject obtained in the authenticator step with further information, required by either the endpoint of the upstream service itself or an authorizer step. This can be handy if the actual authentication system doesn't have all information about the subject (which is usually the case in microservice architectures), or if dynamic information about the subject, like the current location based on the IP address, is required.
* [Mutators]({{< ref "mutators.md">}}) finalize the successful execution of the pipeline and transform the available information about the subject into a format expected, respectively required by the upstream service. This ranges from adding a query parameter, to a structured JWT in a specific header.
* [Error Handlers]({{< ref "error_handlers.md">}}) are responsible for execution of logic if any of the handlers described above failed. These range from a simple error response to the client which sent the request to sophisticated handlers supporting complex logic and redirects.

## General Configuration

All of the above said handlers must be configured in the `pipeline` section of Heimdall's configuration as prototypes for usage in the actual rule definition. With other words only those handlers, which have been configured, can then be reused by a rule.

```yaml
pipeline:
  authenticators:
    <list of authenticators>
  authorizers:
    <list of authorizers>
  hydrators:
    <list of hydrators>
  mutators:
    <list of mutators>
  error_handlers:
    <list of error handlers>
```

Each handler configuration entry must contain at least the following properties:

* `id` - The unique identifier of a handler. Identifiers are used to reference the required handler from a rule. You can choose whatever identifier, you want. It is just a name. It must however be unique across all defined handlers of a particular general type (like authenticator, authorizer, etc.).
* `type` - The specific type of pipeline handler.

Depending on a pipeline handler type, there can be an additional `config` property, as the name implies, for the definition of handler's specific configuration. Every handler specific type can be defined as many times as needed in the pipeline definition. However, for those, which don't have a configuration, it doesn't really make sense, as all of them would behave the same way.

For e.g. your authenticator definitions could look like this:

```yaml
pipeline:
  authenticators:
    - id: foo
      type: bar
    - id: baz
      type: bla
      config:
        bla: bar
    - id: zab
      type: bar
    - id: oof
      type: bla
      config:
        bar: bla
```

The above pipeline configures two instances of an imaginary authenticator of a specific type `bar` available via ids `foo` and `zab`, as well as two instances of an imaginary authenticator of a specific type `bla` available via ids `baz` and `oof`. The `baz` and `oof` authenticators are different, as they are configured differently, but `foo` and `zab` authenticators do not have a configuration. So, they behave the same way and there is actually no need to define two instances of them.

In simplest case a rule will just reuse a handler. In more complex cases a rule can reconfigure parts of it (More about rules configuration can be found [here]({{< ref "../rules/_index.md" >}})). Which parts can be reconfigured are handler specific and described in the documentation of each handler.

Here is an example which configures a couple of prototypes:

```yaml
pipeline:
  authenticators:
    - id: noop_authn
      type: noop
    - id: anon_authn
      type: anonymous
    - id: opaque_auth_token_authn
      type: oauth2_introspection
      config:
        introspection_endpoint:
          url: http://hydra:4445/oauth2/introspect
      assertions:
        issuers:
          - http://127.0.0.1:4444/
  authorizers:
    - id: allow_all_authz
      type: allow
    - id: deny_all_authz
      type: deny
    - id: local_authz
      type: local
      config:
        script: |
          if (!heimdall.subject.Attributes.group_manager.groups["foo"]) {
            raise("user not in the expected group")
          }
  hydrators:
    - id: group_manager
      type: generic
      config:
        endpoint:
          url: http://group-manager.local/groups
          method: GET
        forward_headers:
          - Authorization
        cache_ttl: 1m
  mutators:
    - id: noop_mut
      type: noop
    - id: jwt_mut
      type: jwt
      config:
        ttl: 5m
        claims: |
            {
              {{ $user_name := .Attributes.identity.user_name -}}
              "email": {{ quote .Attributes.identity.email }},
              "email_verified": {{ .Attributes.identity.email_verified }},
              {{ if $user_name -}}
              "name": {{ quote $user_name }}
              {{ else -}}
              "name": {{ quote $email }}
              {{ end -}}
            }
  error_handlers:
    - id: default
      type: default
    - id: authenticate_with_kratos
      type: redirect
      config:
        to: http://127.0.0.1:4433/self-service/login/browser
        return_to_query_parameter: return_to
        when:
          - error:
              - unauthorized
              - forbidden
            request_headers:
              Accept:
                - text/html
```

## Templating

Some pipeline handlers support templating using [Golang Text Templates](https://golang.org/pkg/text/template/). To ease the usage, all [sprig](http://masterminds.github.io/sprig/) functions as well as a `urlenc` function are available. Latter is handy if you need to add e.g. a query parameter to the original request and encode it properly. In addition to the above said functions, heimdall makes the following objects available to the template:

* `subject` - to provide access to all attributes available for the given subject. The access is read only.
* `ctx` - to provide access to the actual HTTP request, like headers, cookies, URL, etc. The access is read only

Examples are provided as part of handler description supporting scripting.

## Scripting

Some authorizers, which verify the presence or values of particular attributes of the subject can make use of [ECMAScript 5.1(+)](https://262.ecma-international.org/5.1/). Heimdall uses [goja](https://github.com/dop251/goja) as ECMAScript engine. In addition to the general ECMAScript functionality, heimdall makes the following functions and object available to the script:

* `console.log` - to log the activities in the script. Can become handy during development of debugging. The output is only available if `debug` log level is set.
* `heimdall.subject` - to provide access to all attributes available for the given subject. The access is read only.
* `heimdall.ctx` - to provide access to the actual HTTP request, like headers, cookies, URL, etc. You can only add new elements (like headers, query parameter), but not change existing.

Examples are provided as part of handler description supporting scripting.