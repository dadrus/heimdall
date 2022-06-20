---
title: "Default Rule"
date: 2022-06-09T22:13:32+02:00
draft: true
menu:
  docs:
    weight: 10
    parent: "Rules"
---

Heimdall lets you not only define upstream service specific rules, it does also support a definition of an optional default rule, which, if defined, kicks in, if no other rule matches. This way you can ensure secure defaults by simultaneously reducing the amount of work while defining upstream service API specific rules. That is, an upstream service API specific rule can reuse definitions from the default rule.

The configuration of the default rule can be done by making use of the `default` property and configuring the following options.

| Name                | Type                                                                                   | Mandatory | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|---------------------|----------------------------------------------------------------------------------------|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `methods`           | *string array*                                                                         | no        | Which HTTP methods (`GET`, `POST`, `PATCH`, etc) are allowed. Defaults to an empty array. If the default rule is defined and the upstream service API specific rule (see also [Rule Definition]({{< relref "rule_definition.md" >}})) does not override it, no methods will be accepted, effectively resulting in `405 Method Not Allowed` response to Heimdall's client for any urls matched by that particular rule.                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `execute`           | *[Regular Pipeline]({{< relref "rule_definition.md#regular-pipeline" >}})*             | yes       | Which handlers to use to authenticate, authorize, hydrate (enrich) and mutate the subject of the request. At least one [authenticator]({{< relref "/docs/configuration/pipeline/authenticators.md" >}}) and one [mutator]({{< relref "/docs/configuration/pipeline/mutators.md" >}}) must be defined. A specific rule (see also [Rule Definition]({{< relref "rule_definition.md" >}})) can omit the definition of authenticators, if it wants to reuse the authenticators defined in the default rule. Same is true for other handlers. Exception are [authorizers]({{< relref "/docs/configuration/pipeline/authorizers.md" >}}) and [hydrators]({{< relref "/docs/configuration/pipeline/hydrators.md" >}}). As soon, as a specific rule defines at least one authorizer or hydrator, those authorizers and hydrators (defined in the default rule) are not considered any more. | 
| `on_error`          | *[Error Handler Pipeline]({{< relref "rule_definition.md#error-handler-pipeline" >}})* | yes       | Which error handlers to use if any of the handlers, defined in the `execute` property, fails. Allows omitting the definition of error handlers in specific rules. As soon as a specific rule defines at least one error handler, all error handlers, defined in the default rule are ignored.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |

**Example**

```yaml
rules:
  default:
    methods:
      - GET
      - PATCH
    execute:
      - authenticator: session_cookie_from_kratos_authn
      - authenticator: oauth2_introspect_token_from_keycloak_authn
      - authorizer: deny_all_requests_authz
      - mutator: jwt_mut
    on_error:
      - error_handler: authenticate_with_kratos_eh
```

This example defines a default rule, which allows HTTP `GET` and `PATCH` requests on any URL (will response with `405 Method Not Allowed` for any other HTTP method used by a client). The regular pipeline consists of two authenticators, with `session_cookie_from_kratos_authn` being the first and `oauth2_introspect_token_from_keycloak_authn` being the fallback (if the first one fails), a `deny_all_requests_authz` authorizer and the `jwt_mut` mutator. The error pipeline is configured to execute only the `authenticate_with_kratos_eh` error handler.

Obviously, the regular pipeline (defined in the `execute` property) of this default rule definition will always result in an error due to `deny_all_requests_authz`. This way it is though to provide secure defaults and let the upstream specific rules override at least the part dealing with authorization. Such an upstream specific rule could then look like follows:

```yaml
id: rule:my-service:protected-api
url: http://my-service.local/foo
execute:
  - authorizer: allow_all_requests_authz
```

Take a look at how `methods`, `on_error`, as well as the authenticators and mutators from the `execute` definition of the default rule are reused. Easy, no?
 
