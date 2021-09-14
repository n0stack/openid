# openid

[![Go Reference](https://pkg.go.dev/badge/go.n0stack.dev/lib/openid.svg)](https://pkg.go.dev/go.n0stack.dev/lib/openid)

This openid repository is a OpenID Connect client library for Golang.

## Usage

```
go get -u go.n0stack.dev/lib/openid
```

**[View the examples here](./examples)**

## Supporting features

- [RFC 6749: The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
  - [x] 4.1. Authorization Code Grant
  - [ ] 4.2. Implicit Grant [DEPRECATED]
  - [ ] 4.3. Resource Owner Password Credentials Grant [DEPRECATED]
  - [x] 4.4. Client Credentials Grant
  - [x] 6. Refreshing an Access Token
- [RFC 7636: Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
  - [ ] plain
  - [x] S256
- [RFC 7523: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523)
  - [ ] 2.1. Using JWTs as Authorization Grants
  - [x] 2.2. Using JWTs for Client Authentication
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
  - [x] 2. ID Token / 3.1.3.7. ID Token Validation / 5.1. Standard Claims
  - [x] 3.1. Authentication using the Authorization Code Flow
  - [ ] 3.2. Authentication using the Implicit Flow [DEPRECATED]
  - [ ] 3.3. Authentication using the Hybrid Flow
  - [ ] 5.3. UserInfo Endpoint
  - [x] 10.1.1. Rotation of Asymmetric Signing Keys
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
  - [ ] `/.well-known/webfinger`
  - [x] `/.well-known/openid-configuration`
- [OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
  - [ ] Poll Mode
  - [ ] Ping Mode
  - [ ] Push Mode
- OAuth 2.1
- Others
  - [x] `urn:ietf:wg:oauth:2.0:oob` [DEPRECATED]
    - https://mailarchive.ietf.org/arch/msg/oauth/OCeJLZCEtNb170Xy-C3uTVDIYjM/
