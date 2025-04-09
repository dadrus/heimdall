# Docker Compose Quickstarts

This directory contains examples described in the getting started section of the documentation. The demonstration of the decision operation mode is done via integration with some reverse proxies.

**Note:** The main branch may have breaking changes (see pending release PRs for details under https://github.com/dadrus/heimdall/pulls) which would make the usage of the referenced heimdall images impossible (even though the configuration files and rules reflect the latest changes). In such situations you'll have to use the `dev` image, build a heimdall image by yourself and update the setups to use it, or switch to a tagged (released) version.


# Proxy Mode Quickstart

In that setup heimdall is not integrated with any other reverse proxy.

1. Start the environment with

   ```bash
   docker compose -f docker-compose.yaml -f docker-compose-proxy.yaml up
   ```

2. Play with it

   ```bash
   curl -v http://127.0.0.1:9090/public
   curl -v http://127.0.0.1:9090/private
   curl -v http://127.0.0.1:9090/user
   curl -v -H "Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIiwidHlwIjoiSldUIn0.eyJleHAiOjIwMjUxMDA3NTEsImlhdCI6MTcwOTc0MDc1MSwiaXNzIjoiZGVtb19pc3N1ZXIiLCJqdGkiOiIzZmFmNDkxOS0wZjUwLTQ3NGItOGExMy0yOTYzMjEzNThlOTMiLCJuYmYiOjE3MDk3NDA3NTEsInJvbGUiOiJ1c2VyIiwic3ViIjoiMiJ9.W5xCpwsFShS0RpOtrm9vrV2dN6K8pRr5gQnt0kluzLE6oNWFzf7Oot-0YLCPa64Z3XPd7cfGcBiSjrzKZSAj4g" 127.0.0.1:9090/user
   curl -v -H "Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIiwidHlwIjoiSldUIn0.eyJleHAiOjIwMjUxMDA3NTEsImlhdCI6MTcwOTc0MDc1MSwiaXNzIjoiZGVtb19pc3N1ZXIiLCJqdGkiOiI0NjExZDM5Yy00MzI1LTRhMWYtYjdkOC1iMmYxMTE3NDEyYzAiLCJuYmYiOjE3MDk3NDA3NTEsInJvbGUiOiJhZG1pbiIsInN1YiI6IjEifQ.mZZ_UqC8RVzEKBPZbPs4eP-MkXLK22Q27ZJ34UwJiioFdaYXqYJ4ZsatP0TbpKeNyF83mkrrCGL_pWLFTho7Gg" 127.0.0.1:9090/admin
   ```
   
   Check the responses

# Decision Mode with Traefik

In that setup heimdall is integrated with Traefik. All requests are sent to traefik, which then contacts heimdall as external authorization middleware and depending on the response from heimdall either forwards the request to the upstream service, or directly responses with an error from heimdall.

*NOTE:* This setup uses Traefik's Docker provider and mounts the `docker.sock` file into the Traefik container. Your docker installation may differ requiring a modification of the configured volume mount in the `docker-compose-traefik.yaml` file.

1. Start the environment with

   ```bash
   docker compose -f docker-compose.yaml -f docker-compose-traefik.yaml up
   ```

2. Play with it

   ```bash
   curl -v http://127.0.0.1:9090/public
   curl -v http://127.0.0.1:9090/private
   curl -v http://127.0.0.1:9090/user
   curl -v -H "Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIiwidHlwIjoiSldUIn0.eyJleHAiOjIwMjUxMDA3NTEsImlhdCI6MTcwOTc0MDc1MSwiaXNzIjoiZGVtb19pc3N1ZXIiLCJqdGkiOiIzZmFmNDkxOS0wZjUwLTQ3NGItOGExMy0yOTYzMjEzNThlOTMiLCJuYmYiOjE3MDk3NDA3NTEsInJvbGUiOiJ1c2VyIiwic3ViIjoiMiJ9.W5xCpwsFShS0RpOtrm9vrV2dN6K8pRr5gQnt0kluzLE6oNWFzf7Oot-0YLCPa64Z3XPd7cfGcBiSjrzKZSAj4g" 127.0.0.1:9090/user
   curl -v -H "Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIiwidHlwIjoiSldUIn0.eyJleHAiOjIwMjUxMDA3NTEsImlhdCI6MTcwOTc0MDc1MSwiaXNzIjoiZGVtb19pc3N1ZXIiLCJqdGkiOiI0NjExZDM5Yy00MzI1LTRhMWYtYjdkOC1iMmYxMTE3NDEyYzAiLCJuYmYiOjE3MDk3NDA3NTEsInJvbGUiOiJhZG1pbiIsInN1YiI6IjEifQ.mZZ_UqC8RVzEKBPZbPs4eP-MkXLK22Q27ZJ34UwJiioFdaYXqYJ4ZsatP0TbpKeNyF83mkrrCGL_pWLFTho7Gg" 127.0.0.1:9090/admin
   ```

   Check the responses

# Decision Mode with Envoy

In that setup heimdall is integrated with Envoy Proxy. All requests are sent to envoy, which then contacts heimdall as external authorization middleware and depending on the response from heimdall either forwards the request to the upstream service, or directly responses with an error from heimdall.

1. Start the environment with
   ether

   ```bash
   docker compose -f docker-compose.yaml -f docker-compose-envoy-http.yaml up
   ```
   
   to see integration over HTTP in action, or

   ```bash
   docker compose -f docker-compose.yaml -f docker-compose-envoy-grpc.yaml up
   ```

   to see the envoy GRPC extauthz integration in action (not available before v0.7.0-alpha).

2. Play with it

   ```bash
   curl -v http://127.0.0.1:9090/public
   curl -v http://127.0.0.1:9090/private
   curl -v http://127.0.0.1:9090/user
   curl -H "Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIiwidHlwIjoiSldUIn0.eyJleHAiOjIwMjUxMDA3NTEsImlhdCI6MTcwOTc0MDc1MSwiaXNzIjoiZGVtb19pc3N1ZXIiLCJqdGkiOiIzZmFmNDkxOS0wZjUwLTQ3NGItOGExMy0yOTYzMjEzNThlOTMiLCJuYmYiOjE3MDk3NDA3NTEsInJvbGUiOiJ1c2VyIiwic3ViIjoiMiJ9.W5xCpwsFShS0RpOtrm9vrV2dN6K8pRr5gQnt0kluzLE6oNWFzf7Oot-0YLCPa64Z3XPd7cfGcBiSjrzKZSAj4g" 127.0.0.1:9090/user
   curl -H "Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIiwidHlwIjoiSldUIn0.eyJleHAiOjIwMjUxMDA3NTEsImlhdCI6MTcwOTc0MDc1MSwiaXNzIjoiZGVtb19pc3N1ZXIiLCJqdGkiOiI0NjExZDM5Yy00MzI1LTRhMWYtYjdkOC1iMmYxMTE3NDEyYzAiLCJuYmYiOjE3MDk3NDA3NTEsInJvbGUiOiJhZG1pbiIsInN1YiI6IjEifQ.mZZ_UqC8RVzEKBPZbPs4eP-MkXLK22Q27ZJ34UwJiioFdaYXqYJ4ZsatP0TbpKeNyF83mkrrCGL_pWLFTho7Gg" 127.0.0.1:9090/admin
   ```

   Check the responses