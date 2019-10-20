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

# Login Mechanism

How do we make sure ssh sends the right cert?

We have a couple options, either one implies we authenticate to a local agent, which is granted credentials to communicate with the CA to obtain short lived certificates. We must never *trust* the agent to do more than obtain certs on behalf of the person whom it has credentials for -- ie, it must never get the CA private key.

## Option: custom ssh-agent and `IdentityAgent` directives on host patterns

No interest in replacing default openssh ssh-agent, but you can specify a different one for a host block in config. I don't know if there is a mechanism to launch it if missing, but worst case we need to start a daemon.

We then need to have a communication channel between that agent and the CA which we trust. It seems like starting the agent explicitely and doing an auth dance (CLI saml with okta, pop a web browser, etc) that tells the CA to trust the agent can work. Implies we could use short lived TLS certs for Agent -> CA, though this may be overthinking it.

## Option: daemon generate cert file

Instead of asking the agent for the cert, just update contents of `~/.ssh/` to replace a named certificate. A drawback here is that we don't know when it is being used, so refreshing it will need to be out of band.

This feels like it would be faster to start with, but more limited than having an agent proper.


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
out="$(echo $1 | base64 -D)"
echo "meow $out" >&2
```