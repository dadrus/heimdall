---
title: "Hydrators"
date: 2022-06-09T18:57:10+02:00
lastmod: 2022-06-09T18:57:10+02:00
description: ""
lead: ""
draft: true
images: []
weight: 999
toc: true
menu:
  docs:
    weight: 30
    parent: "Pipeline"
---

Hydrators enrich the information about the subject obtained in the authenticator step with further information, required by either the endpoint of the upstream service itself or an authorizer step. This can be handy if the actual authentication system doesn't have all information about the subject (which is usually the case in microservice architectures), or if dynamic information about the subject, like the current location based on the IP address, is required.

<!--more-->