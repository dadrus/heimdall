---
title: "Authorizers"
date: 2022-06-09T18:57:03+02:00
lastmod: 2022-06-09T18:57:03+02:00
description: ""
lead: ""
draft: true
images: []
weight: 999
toc: true
menu:
  docs:
    weight: 20
    parent: "Pipeline"
---

Authorizers ensure that the subject obtained via an authenticator step has the required permissions to submit the given HTTP request and thus to execute the corresponding logic in the upstream service. E.g. a specific endpoint of the upstream service might only be accessible to a "user" from the "admin" group, or to an HTTP request if a specific HTTP header is set.

<!--more-->