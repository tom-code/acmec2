# acmec
personal acme client - to get certificates from letsencrypt
tested with pebble, staging and production

https://tools.ietf.org/html/rfc8555

- http-01: it launches its own web server - so it is required to have www-proof port free - only port 80 is supported by letsencrypt :unamused:
- dns-01: launches own dns server serving only appropriate TXT record - domain delegation must be used

## staging example

```
./acme  -u https://acme-staging-v02.api.letsencrypt.org/directory acc-create
./acme  -u https://acme-staging-v02.api.letsencrypt.org/directory -p 80 order my.domain
./acme  -u https://acme-staging-v02.api.letsencrypt.org/directory -p 80 order my.domain -t http-01
./acme  -u https://acme-staging-v02.api.letsencrypt.org/directory -p 80 order my.domain -t dns-01
```

## production example
```
./acme  -u https://acme-v02.api.letsencrypt.org/directory acc-create
./acme  -u https://acme-v02.api.letsencrypt.org/directory -p 80 order my.domain
```
