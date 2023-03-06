# Docker Compose Quickstarts

This directory contains examples described in the getting started section of the documentation. The demonstration of the decision operation mode is done via integration with some reverse proxies.

# Proxy Mode Quickstart

In that setup heimdall is not integrated with any other reverse proxy.

1. Start the environment with

   ```bash
   docker-compose -f docker-compose.yaml -f docker-compose-proxy.yaml up
   ```

2. Play with it

   ```bash
   curl -v http://127.0.0.1:9090/anonymous
   curl -v http://127.0.0.1:9090/public
   curl -v http://127.0.0.1:9090/foo
   curl -v -H "Accept: Bar" http://127.0.0.1:9090/foo
   ```
   
   Check the responses

# Decision Mode with Traefik

In that setup heimdall is integrated with Traefik. All requests are sent to traefik, which then contacts heimdall as external authorization middleware and depending on the response from heimdall either forwards the request to the upstream service, or directly responses with an error from heimdall.

1. Start the environment with

   ```bash
   docker-compose -f docker-compose.yaml -f docker-compose-traefik.yaml up
   ```

2. Play with it

   ```bash
   curl -v http://127.0.0.1:9090/anonymous
   curl -v http://127.0.0.1:9090/public
   curl -v http://127.0.0.1:9090/foo
   curl -v -H "Accept: Bar" http://127.0.0.1:9090/foo
   ```

   Check the responses

# Decision Mode with Envoy

In that setup heimdall is integrated with Envoy Proxy. All requests are sent to envoy, which then contacts heimdall as external authorization middleware and depending on the response from heimdall either forwards the request to the upstream service, or directly responses with an error from heimdall.

1. Start the environment with
   ether

   ```bash
   docker-compose -f docker-compose.yaml -f docker-compose-envoy-http.yaml up
   ```
   
   to see integration using the HTTP decision service in action, or

   ```bash
   docker-compose -f docker-compose.yaml -f docker-compose-envoy-grpc.yaml up
   ```

   to see integration using the envoy GRPC extauthz decision service in action (not available before v0.7.0-alpha).

2. Play with it

   ```bash
   curl -v http://127.0.0.1:9090/anonymous
   curl -v http://127.0.0.1:9090/public
   curl -v http://127.0.0.1:9090/foo
   curl -v -H "Accept: Bar" http://127.0.0.1:9090/foo
   ```

   Check the responses