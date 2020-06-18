# DFN PKI SOAP Client Test

This is work in progress. Use at your own risk.

## Build and publish the docker image

Run 

```bash
docker build -t farberg/dfn-soap-client-test:latest .

docker push farberg/dfn-soap-client-test:latest
```

## Run in Docker

You need the following data supplied by the [DFN PKI](https://www.pki.dfn.de/ueberblick-dfn-pki/)
- Client certificate for authentication (assumed to be stored in folder `$PWD/private` in the following example)
- Password required to access the certificate
- `ra id` (cf. DFN docs)
- `CA name` (e.g., `test-client1-ca`)

Then run

```bash
docker run --rm -ti -v "$PWD/private:/data" farberg/dfn-soap-client-test -ra-id 1234 -p12file /data/your-cert.p12 -password your-pw
```

## Acknowledgement

Libraries used and included in this repository
- This product includes software developed by DFN-CERT Services GmbH, Hamburg, Germany and its contributors. (cf. [SOAP-Client Version 3.8.1/4.0.2](https://blog.pki.dfn.de/2019/11/soap-client-version-3-8-1-4-0-2/))
- [kohsuke/args4j](https://github.com/kohsuke/args4j)
- [Bouncycastle](https://www.bouncycastle.org/)
