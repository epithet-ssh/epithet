# Epithet makes SSH certificates easy

[![Actions Status](https://github.com/brianm/epithet/workflows/build/badge.svg)](https://github.com/brianm/epithet/actions) [![Go Reportcard](https://goreportcard.com/badge/github.com/brianm/epithet)](https://goreportcard.com/report/github.com/brianm/epithet) [![Maintainability](https://api.codeclimate.com/v1/badges/3a4020265b38c175bdf0/maintainability)](https://codeclimate.com/github/brianm/epithet/maintainability)

Epithet provides an SSH Agent and a CA Service which work together to provide a series of short lived (typically a few minutes) SSH certificates to users. Authentication is (generally) completed on the client, providing an authentication token to the Agent. The Agent then passes the `{token, public-key}` pair to the CA service. The CA service then passes the token to a Policy service which performs authorization and returns certificate parameters (such as the principals, certificate expiration, and allowed extensions) to the CA. The CA then signs the certificate using the parameters from the policy server and returns it to the Agent.

The Agent will re-use an authentication token until it stops working. A typical deployment might use OIDC or SAML to authenticate users, in which case the token will be a JWT access token (or SAML analogue), but could just be a username/password/mfa challenge, or even a shared secret.

The Agent generates a new keypair when it starts, and never exposes the private key or writes it to disk. The CA loads the private key, and also never exposes it or writes it to disk.

```
+-------+          +---------------+       +-------+                 +-----+          +---------+
| User  |          | Authenticator |       | Agent |                 | CA  |          | Policy  |
+-------+          +---------------+       +-------+                 +-----+          +---------+
    |                      |                   |                        |                  |
    | Authenticate         |                   |                        |                  |
    |--------------------->|                   |                        |                  |
    |                      |                   |                        |                  |
    |                      | Provide token     |                        |                  |
    |                      |------------------>|                        |                  |
    |                      |                   |                        |                  |
    |                      |                   | Request Certificate    |                  |
    |                      |                   |----------------------->|                  |
    |                      |                   |                        |                  |
    |                      |                   |                        | Authorize        |
    |                      |                   |                        |----------------->|
    |                      |                   |                        |                  |
    |                      |                   |                        |      Cert Params |
    |                      |                   |                        |<-----------------|
    |                      |                   |                        |                  |
    |                      |                   |            Certificate |                  |
    |                      |                   |<-----------------------|                  |
    |                      |                   |                        |                  |
    | Use SSH              |                   |                        |                  |
    |----------------------------------------->|                        |                  |
    |                      |                   |                        |                  |
    |                      |                   | Cert Expires           |                  |
    |                      |                   |-------------           |                  |
    |                      |                   |            |           |                  |
    |                      |                   |<------------           |                  |
    |                      |                   |                        |                  |
    | Use SSH              |                   |                        |                  |
    |----------------------------------------->|                        |                  |
    |                      |                   |                        |                  |
    |                      |                   | Request Certificate    |                  |
    |                      |                   |----------------------->|                  |
    |                      |                   |                        |                  |
    |                      |                   |                        | Authorize        |
    |                      |                   |                        |----------------->|
    |                      |                   |                        |                  |
    |                      |                   |                        |      Cert Params |
    |                      |                   |                        |<-----------------|
    |                      |                   |                        |                  |
    |                      |                   |            Certificate |                  |
    |                      |                   |<-----------------------|                  |
    |                      |                   |                        |                  |
```

# Setting up clients

Users will typically specify the use of the Epithet SSH Agent for a hostname pattern:

```
Host *.example.com
     User brianm
     IdentityAgent ~/.epithet/example-agent.sock
```

# Running a CA

# Creating a Policy Service



