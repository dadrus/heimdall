---
title: "Pipeline"
date: 2022-06-09T18:56:56+02:00
lastmod: 2022-06-09T18:56:56+02:00
description: ""
lead: ""
draft: true
images: []
weight: 999
toc: true
menu:
  docs:
    parent: ""
---

# Pipeline

This section explains the available pipeline handlers and mechanisms in detail. Before diving onto the details of these, we recommend to make yourself familiar with the principal architecture and components.

The general pipeline handlers are:

* Authenticators inspect HTTP requests, like the presence of a specific cookie, which represents the authentication session of the subject with the service and execute logic required to obtain information about that subject. A subject, could be a user who tries to use particular functionality of the upstream service, a machine (if you have machine-2-machine interaction), or something different. Authenticators ensure the subject has already been authenticated and the information available about it is valid.
* Authorizers ensure that the subject obtained via an authenticator step has the required permissions to submit the given HTTP request and thus to execute the corresponding logic in the upstream service. E.g. a specific endpoint of the upstream service might only be accessible to a "user" from the "admin" group, or to an HTTP request if a specific HTTP header is set.
* Hydrators enrich the information about the subject obtained in the authenticator step with further information, required by either the endpoint of the upstream service itself or an authorizer step. This can be handy if the actual authentication system doesn't have all information about the subject (which is usually the case in microservice architectures), or if dynamic information about the subject, like the current location based on the IP address, is required.
* Mutators finalize the successful execution of the pipeline and transform the available information about the subject into a format expected, respectively required by the upstream service. This ranges from adding a query parameter, to a structured JWT in a specific header.
* Error Handlers are responsible for execution of logic if any of the handlers described above failed. These range from a simple error response to the client which sent the request to sophisticated handlers supporting complex logic and redirects. 

## Templating

All pipeline handlers, except error handlers, support templating using [Golang Text Templates](https://golang.org/pkg/text/template/). To ease the usage, all [sprig](http://masterminds.github.io/sprig/) functions as well as a `urlenc` function are available. Latter is handy if you need to add e.g. a query parameter to the original request and encode it properly. In addition to the above said functions, heimdall makes the following objects available to the template:

* `subject` - to provide access to all attributes available for the given subject. The access is read only.
* `ctx` - to provide access to the actual HTTP request, like headers, cookies, URL, etc. The access is read only.

Examples are provided as part of handler description supporting scripting.

## Scripting

Some authorizers, which verify the presence or values of particular attributes of the subject can make use of [ECMAScript 5.1(+)](https://262.ecma-international.org/5.1/). Heimdall uses [goja](https://github.com/dop251/goja) as ECMAScript engine. In addition to the general ECMAScript functionality, heimdall makes the following functions and object available to the script:

* `console.log` - to log the activities in the script. Can become handy during development of debugging. The output is only available if `debug` log level is set.
* `heimdall.subject` - to provide access to all attributes available for the given subject. The access is read only.
* `heimdall.ctx` - to provide access to the actual HTTP request, like headers, cookies, URL, etc. The access is read only.

Examples are provided as part of handler description supporting scripting.