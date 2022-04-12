# Heimdall

Heimdall is inspired by [Ory's OAthkeeper](https://www.ory.sh/docs/oathkeeper), tries however to resolve the functional limitations of that product by also building on a more modern technology stack resulting in a much simpler and faster implementation.

Heimdall authenticates and authorizes incoming HTTP requests as well as enriches these with further information and transforms resulting subject information to a format, both required by the upstream services. It is supposed to be used either as a Reverse Proxy in front of your upstream API or web server that rejects unauthorized requests and forwards authorized ones to your end points, or as a Decision API, which integrates with your API Gateway (Kong, NGNIX, Envoy, Traefik, etc) and then acts as a Policy Decision Point.

The current implementation is a pre alpha version, which alreay supports

* Decision API
* Loading rules from the file system
* Different authenticator types (allow, deny, jwt, oauth2 introspection, generic)
* Declarative authorizers (allow, deny)
* Mutators (opaque cookie, opaque header, jwt in the Authorization header) to transform the subject information
* Error Handlers (default, redirect, www-authenticate), which support accept type negotiation as well

Features to come are:

* Reverse Proxy
* Hydrators - to enrich the subject information retrieved from the authenticator
* Authorizer (remote) - to make use of an external authorization system.
* k8s CDRs to load rules from.
* Opentracing support

