---
title: mechanism to tunnel auth to remote agent
id: gszy91dg
created: 2025-12-01T18:36:44.286521Z
updated: 2025-12-01T18:44:18.630502Z
author: Brian McCallister
priority: medium
---

It would eb good to have a mechanism to tunnel auth protocol stuff to a remote host. 

Imagine this scenario:

Endpoint: laptop1
Server: shell1
Servers: host1, host2, host3

User is physically present on laptop1, but wants to be able to run epithet on shell1, say because the CA is only available on an internal network, so calls to the CA need to happen from shell1 instead of laptop1.

We can only pop a browser on laptop1, though, so the auth plugin needs to run on laptop1, but controlled by epithet on shell1.

Possible approaches:

- have a special agent that can run on the endpoint which tunnels auth stuff over an agent protocol extension
- spin up an ssh stream against an epithet remote from laptop1 to shell1. This would be like vscode remoting stuff, maybe
- Can we do either of these via a jumphost setup? 

Either way, I think we are going to wind up with a special agent version that runs on the endpoint, which is not going to play nicely with the way ssh likes to tunnel things for jumphsost.

This is goign to require some thinking

---
## Log

### 2025-12-01T18:36:44Z Brian McCallister

Created task.