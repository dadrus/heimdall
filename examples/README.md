# Examples

This directory contains different examples related to heimdall usage and setup.

Those examples, which are based on docker compose are located in the `docker-compose` directory and those, which are implemented for Kubernetes, are located in `kubernetes` directory.

**Warning:** For the sake of simplicity, the examples use insecure settings, such as lacking TLS or similar protections. These configurations are intended solely for demonstration and are not suitable for production environments.

**Note:** The main branch may have breaking changes (see pending release PRs for details under https://github.com/dadrus/heimdall/pulls) which would make the usage of the referenced heimdall images impossible (even though the configuration files and rules reflect the latest changes). In such situations you'll have to use the `dev` image, build a heimdall image by yourself and update the setups to use it, or switch to a tagged (released) version.