# Examples

- [authorization code grant with confidential client](./authorization-code-grant-with-confidential-client)
  - authorization code grant
  - confidential client which is authenticated by client secret
- [authorization code grant with public client](./authorization-code-grant-with-public-client)
  - authorization code grant
  - public client
- [authorization code grant with OOB](./authorization-code-grant-with-oob)
  - authorization code grant with OOB (out of band)
  - confidential client which is authenticated by client secret
- [client-credentials-grant](./client-credentials-grant)
  - client credentials grant
  - confidential client which is authenticated by bearer-jwt


## Usage

1. Up keycloak

```
docker-compose up -d
```

2. Run examples

```
cd authorization-code-grant-with-public-client
go run main.go
```

If example code open a login prompt, use below information.

| Username | Password |
| -- | -- |
| examples | password |
