# epithet makes secure ssh certificate AAA easy

## Authentication

Short lived SSH certs.

What is short-live default? 10 minutes, 1 hour? How do we arrive at a sound number rather than a "this sounds good"?

How do we authenticate to the CA service? This seems like it should be pluggable (SAML, OAuth, OpenID)

## Authorization

By principals-as-groups rather than principals-as-people.

How much should we care about individuals vs groups? My tendency is to steer to principal being the group not the individual, then manage who is in what group in the cert generating machinery. 

## Accounting (Auditing)

Use cert ID to know who did what.

[Facebook style](https://engineering.fb.com/security/scalable-and-secure-access-with-ssh/) ssh handling seems to take this approach. 

# Auth Mechanism

We must never *trust* the agent to do more than obtain certs on behalf of the person whom it has credentials for -- ie, it must never get the CA private key.

Policy in the CA must control the specific configuration of the cert (principals, duration, name, etc). All the agent may do is ask for the next cert on behalf of the authentication tokens it has, it must not ever specifcy what goes in the certificate.

## Custom ssh-agent and `IdentityAgent` directives on host patterns

No interest in replacing default openssh ssh-agent, but you can specify a different one for a host block in config. I don't know if there is a mechanism to launch it if missing, but worst case we need to start a daemon.

We then need to have a communication channel between that agent and the CA which we trust. It seems like starting the agent explicitely and doing an auth dance (CLI saml with okta, pop a web browser, etc) that tells the CA to trust the agent can work. Implies we could use short lived TLS certs for Agent -> CA, though this may be overthinking it.


# "Installation"

Seems critical that an installation needs to run its own CA for security, so we need to make CA setup process as one-click as we can. For v1, seems fine to assume AWS will host, but am sure by v7 we will need to not care, so don't make decisions that lock us in to a single infra, but don't worry about supporting multiple infrastructures yet.

# Agent Workings

```
agent starts -> generates new keypair
             -> invokes authenticator to get token
                <- authToken
             -> calls CA using authToken to ask for certificate
                <- (certificate, sessionToken)
             -> publishes auth socket (and does whatever it is supposed to)

cert expires -> calls CA using sessionToken
                <- (certificate, sessionToken) 
             -> replaces cert in agent
             -> uses the new sessionToken going forward

cert expires -> calls CA using sessionToken
                <- (authExpired) 
             -> remove keys from keyring
             -> IF CAN REAUTH: ask for new authentication
                ELSE: ???? EXPLOSION ????
```

The `sessionToken` from the ca is an encrypoted blob with the state the CA needs to
reestablish the session. In Okta, for example, it would contain the encrypted `sid`.

## Authentication Expiration/Failure

UI here is tricky as ssh-agent will generally be a daemon. A native app to request re-auth would work, but we also  need a pure-cli approach. Easiest is probably just train users to re-auth when they start getting ssh failures. We need some affordance to indicate this to them however, as no one reads docs if they can help it.

# CA Workings

CA only offers two functions, retrieve the public key and generate certificate. 

Cert requests will include the authn provider, which will be used to select a corresponding authn provider on the CA side (to convert a sessionToken to a sessionID in an Okta case, for example). Any brokered informatiuon (such as the session in an Okta case) must not be sent back to the agent.

CA, sadly, needs to keeep some state in order to prevent replay attacks. There may be some clever protocol to prevent them by embedding information in refresh tokens, but I doubt it.

When granting a cert, the CA MAY return a refresh token that can be used to generate the next certificate using the built in authn provider `refresh`. The CA must prevent reuse of these tokens, and refresh must be able to tie back to the originating authn.

# Plugins

Plugins for authentication (or other things eventually) work on a simple
subprocess model. The input is passed as a base64 encoded command line argument
to the plugin process, and stderr is returned as the plugin result. This leaves
stdin and stdout attached to the standard stdin/stdout so that the plugin may
interract with the user. Exit value of 0 is a success, anything else is an error.

In the case of an error, the stderr output will be the error message.

Simple plugin example from unit tests:

```
#!/usr/bin/env bash
in="$(echo $1 | base64 -D)"
echo "meow $in" >&2
```
