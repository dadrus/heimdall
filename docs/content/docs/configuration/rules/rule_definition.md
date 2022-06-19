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

A single rule consists of the following properties:

| Name                | Type                  | Mandatory | Description                                                                                                                                                                                                                 |
|---------------------|-----------------------|-----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `id`                | *string*              | yes       | The unique identifier of a rule. It must be unique across all rules. To ensure this it is recommended to let the `id` include the name of your upstream service, as well as its purpose. E.g. `rule:my-service:public-api`. |
| `url`               | *string*              | yes       | Glob or Regex pattern of the endpoints of your upstream service, which this rule should apply to.                                                                                                                           |
| `matching_strategy` | *string*              | no        | Which strategy to use for matching of the value, provided in the `url` property. Can be `glob`(default) or `regex`.                                                                                                         |
| `methods`           | *string*              | no        | Which HTTP methods (`GET`, `POST`, `PATCH`, etc) are allowed for the matched url.                                                                                                                                           |
| `execute`           | *Pipeline Definition* | yes       | Which handlers to use to authenticate, authorize, hydrate (enrich) and mutate the subject of the request.                                                                                                                   | 
| `on_error`          | *Error Handler*       | no        | Which error handlers to use if any of the handlers, defined in the `execute` property, fails. This property is optional only, if a default rule has been configured and contains an `on_error` definition.                  |  