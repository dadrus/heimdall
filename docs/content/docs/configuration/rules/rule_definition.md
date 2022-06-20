---
title: "Rule Definition"
date: 2022-06-09T22:13:32+02:00
lastmod: 2022-06-09T22:13:32+02:00
draft: true
menu:
  docs:
    weight: 20
    parent: "Rules"
---

## Rule Configuration

A single rule consists of the following properties:

| Name                | Type                                                                 | Mandatory | Description                                                                                                                                                                                                                                    |
|---------------------|----------------------------------------------------------------------|-----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `id`                | *string*                                                             | yes       | The unique identifier of a rule. It must be unique across all rules. To ensure this it is recommended to let the `id` include the name of your upstream service, as well as its purpose. E.g. `rule:my-service:public-api`.                    |
| `url`               | *string*                                                             | yes       | Glob or Regex pattern of the endpoints of your upstream service, which this rule should apply to. Query parameters are ignored.                                                                                                                |
| `matching_strategy` | *[Matching Strategy]({{< relref "#matching-strategy" >}})*           | no        | Which strategy to use for matching of the value, provided in the `url` property. Can be `glob` or `regex`. Defaults to `glob`.                                                                                                                 |
| `methods`           | *string*                                                             | no        | Which HTTP methods (`GET`, `POST`, `PATCH`, etc) are allowed for the matched url.                                                                                                                                                              |
| `execute`           | *[Regular Pipeline]({{< relref "#regular-pipeline" >}})*             | yes       | Which handlers to use to authenticate, authorize, hydrate (enrich) and mutate the subject of the request.                                                                                                                                      | 
| `on_error`          | *[Error Handler Pipeline]({{< relref "#error-handler-pipeline" >}})* | no        | Which error handlers to use if any of the handlers, defined in the `execute` property, fails. This property is optional only, if a [default rule]({{< relref "default_rule.md" >}}) has been configured and contains an `on_error` definition. |

**Example**

```yaml
id: rule:foo:bar
url: http://my-service.local/<**>
methods:
  - GET
  - POST
execute:
  - authenticator: foo
  - authorizer: bar
  - hydrator: foo
  - mutator: zab
on_error:
  - error_handler: foobar
```

### Matching Strategy

Heimdall uses [dlclark/regexp2](https://github.com/dlclark/regexp2) to match `regex` expressions and [gobwas/glob](https://github.com/gobwas/glob) to match `glob` expressions. Head over to linked resources to get more insights about possible options for expression definitions.

**Regular expressions examples**

* `https://mydomain.com/` matches `https://mydomain.com/` and doesn't match `https://mydomain.com/foo` or `https://mydomain.com`.
* `<https|http>://mydomain.com/<.*>` matches `https://mydomain.com/` and `http://mydomain.com/foo`. Doesn't match `https://other-domain.com/` or `https://mydomain.com`.
* `http://mydomain.com/<[[:digit:]]+>` matches `http://mydomain.com/123`, but doesn't match `http://mydomain/abc`.
* `http://mydomain.com/<(?!protected).*>` matches `http://mydomain.com/resource`, but doesn't match `http://mydomain.com/protected`.

**Glob patterns examples**

* `https://mydomain.com/<m?n>` matches `https://mydomain.com/man` and does not match `http://mydomain.com/foo`.
* `https://mydomain.com/<{foo*,bar*}>` matches `https://mydomain.com/foo` or `https://mydomain.com/bar` and doesn't match `https://mydomain.com/any`.

### Regular Pipeline

As described in the [Architecture Overview]({{< relref "/docs/introduction/architecture.md" >}}), Heimdall's decision pipeline consists of multiple steps - at least consisting of [authenticators]({{< relref "/docs/configuration/pipeline/authenticators.md" >}}) and [mutators]({{< relref "/docs/configuration/pipeline/mutators.md" >}}). The definition of such a pipeline happens as a list of required types with the corresponding ids (previously defined in Heimdall's [Pipeline]({{< relref "/docs/configuration/pipeline/_index.md" >}}) configuration), in the following order:

* List of [authenticators]({{< relref "/docs/configuration/pipeline/authenticators.md" >}}) using `authenticator` as key, followed by the required authenticator `id`. Authenticators following the first defined in the list are used by Heimdall as fallback. That is, if first authenticator fails due to missing authentication data, second is executed, etc. Fallback is not used if an authenticator fails due to validation errors of the given authentication data. E.g. if an authenticator fails to validate the signature of a JWT token, the next authenticator in the list will not be executed. Instead, the entire pipeline will fail and lead to the execution of the [error handler pipeline]({{< relref "#error-handler-pipeline" >}}). This list is mandatory if no [default rule]({{< relref "default_rule.md" >}}) is configured.
* List of [hydrators]({{< relref "/docs/configuration/pipeline/hydrators.md" >}}) and [authorizers]({{< relref "/docs/configuration/pipeline/authorizers.md" >}}) in any order (optional). Can also be mixed. As with authenticators, the list definition happens using either `hydrator` or `authorizer` as key, followed by the required `id`. All handlers in this list are executed in the order, they are defined. If any of these fails, the entire pipeline fails, which leads to the execution of the [error handler pipeline]({{< relref "#error-handler-pipeline" >}}). This list is optional. 
* List [mutators]({{< relref "/docs/configuration/pipeline/mutators.md" >}}) using `mutator` as key, followed by the required mutator `id`. All mutators in this list are executed in the order, they are defined. If any of these fails, the entire pipeline fails, which leads to the execution of the [error handler pipeline]({{< relref "#error-handler-pipeline" >}}). This list is mandatory if no [default rule]({{< relref "default_rule.md" >}}) is configured.

In all cases, parts of the used pipeline type configurations can be overridden if supported by the corresponding pipeline type. Overriding has no effect on the handler prototypes defined in Heimdall's [Pipeline]({{< relref "/docs/configuration/pipeline/_index.md" >}}) configuration. Overrides are always local to the given rule. With other words, you can adjust your rule specific pipeline as you want without any side effects. 

**Example**

```yaml
# list of authenticators
- authenticator: foo
- authenticator: bar
  config:
    subject: anon
  # ... any further required authenticator
# list of authorizers and hydrators in any order
- hydrator: baz
  config:
    cache_ttl: 0s
- authorizer: zab
- hydrator: foo
- hydrator: bar
- authorizer: foo
  config:
    script: |
      // some script logic deviating from the definition in the pipeline configuration.
  # ... any further required authorizer or hydrator
# list of mutators
- mutator: foo
- mutator: bar
  config:
    headers:
    - X-User-ID: {{ quote .ID }}
  # ... any further required mutators
```

This example uses 

* two authenticators, with authenticator named `bar` being the fallback for the authenticator named `foo`. This fallback authenticator is obviously of type [anonymous]({{< relref "/docs/configuration/pipeline/authenticators.md#anonymous" >}}) as it reconfigures the referenced prototype to use `anon` for subject id.
* multiple hydrators and authorizers, with first hydrator having its cache disabled (`cache_ttl` set to 0s) and the last authorizer being of type [local]({{< relref "/docs/configuration/pipeline/authorizers.md#local" >}}) as it reconfigures the referenced prototype to use a different authorization script.
* two mutators, with the second one being obviously of type [header]({{< relref "/docs/configuration/pipeline/mutators.md#header" >}}), as it defines a `X-User-ID` header set to the value of the subject id to be forwarded to the upstream service.

### Error Handler Pipeline

Compared to the [Regular Pipeline]({{< relref "#regular-pipeline" >}}), the error handler pipeline is pretty simple. It is also a list of handlers, but all referenced handler types are [error handler types]({{< relref "/docs/configuration/pipeline/error_handlers.md" >}}). Thus, each entry in this list must have `error_handler` as key, followed by the `ìd` of the required error handler, previously defined in Heimdall's [Pipeline]({{< relref "/docs/configuration/pipeline/_index.md" >}}) configuration. Error handlers are always executed as fallbacks. So, if the condition of the first error handler does not match, second is selected, if its condition matches, it is executed, otherwise the next one is selected, etc. If none of the conditions of the defined error handlers match, the [default error handler]({{< relref "/docs/configuration/pipeline/error_handlers.md#default" >}}) is executed.

As with the regular pipeline, parts of the used error handler configurations can be overridden if supported by the corresponding type. Overriding has no effect on the handler prototypes defined in Heimdall's [Pipeline]({{< relref "/docs/configuration/pipeline/_index.md" >}}) configuration. Overrides are always local to the given rule. With other words, you can adjust your rule specific pipeline as you want without any side effects.

**Example**

```yaml
- error_handler: foo
- error_handler: bar
  config:
    when:
      # rule specific conditions
```

This example uses two error handlers, named `foo` and `bar`. `bar` will only be selected by Heimdall if `foo`'s error condition (defined in Heimdall's [Pipeline]({{< relref "/docs/configuration/pipeline/_index.md" >}}) configuration) does not match. `bar` does also override the default condition, defined by the prototype to the one required, by the given rule. 

## Rule Set

A rule set is just a list of rules, typically defined in a format specified by a particular [provider]({{< relref "providers.md" >}}). In its simplest case, a rule set does not require further configuration options and can look like shown below:

```yaml
- id: rule:1
  url: https://my-service1.local/<**>
  methods: [ "GET" ]
  execute:
    - authorizer: foobar
- id: rule:2
  url: https://my-service2.local/<**>
  methods: [ "GET" ]
  execute:
    - authorizer: barfoo
# further rules
# ...
```