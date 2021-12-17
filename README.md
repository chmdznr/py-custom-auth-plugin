# py-custom-auth-plugin
Custom auth middleware for Tyk using Python

# build bundle.zip command (in windows powershell):
`docker run --rm -w "/tmp" -v ${pwd}:/tmp --entrypoint "/bin/sh" -it tykio/tyk-gateway:v3.2.2 -c '/opt/tyk-gateway/tyk bundle build -y'`

# add `vendor` plugin to bundle.zip:
`zip -r bundle.zip vendor/`
