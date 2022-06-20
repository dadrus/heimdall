---
title: "Rules"
date: 2022-06-09T22:11:50+02:00
draft: true
menu: 
  docs:
    weight: 40
    parent: "Configuration"
---

This section explains how rules can be defined and used in detail. Before diving onto this topic, we recommend to make yourself familiar with the principal architecture and components.

Core aspects of Heimdall are rules. These let Heimdall execute logic required by your upstream service to authenticate, authorize the incoming requests, enrich the information about the subject and mutate it according to the needs of the upstream service. However, to be able to define even a single rule, you must configure [pipeline handlers]({{< relref "/docs/configuration/pipeline/_index.md" >}}), which you can then reference according to your, respectively the needs of your particular upstream service. Rules are dynamic by nature and can come and go together with the upstream service defining these.

All rule specific static configuration can be done by making use of Heimdall's `rules` option.

In general, following three aspects are important when dealing with rules:

* [Rule Definition]({{< relref "rule_definition.md" >}}), which describes the configuration options of a single rule and how the [pipeline handlers]({{< relref "/docs/configuration/pipeline/_index.md" >}}) are used.
* [Providers]({{< relref "providers.md" >}}), which describes available options on how rules can be loaded.
* [Default Rule]({{< relref "default_rule.md" >}}), which describes, how the default rule can be configured and used.

