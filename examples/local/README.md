# Run heimdall locally

You may start the heimdall together with a Redis cache and an example application. You may also ommit the heimdall container and run it from your IDE for debugging instead. 

The folder `certificates` contain test certificates for running the Redis cache in TLS mode. *Do not use these certificates in production!* 
In order to regenerate the certificates, run teh `gen-test-certs.sh` script in the `certificates` directory. You may want to edit the DNS section in the script.