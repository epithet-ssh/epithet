# Epithet makes SSH certificates easy

V2 Changes Everything (for the better!). We keep the agent, but it is no longer an ssh agent. 

```
┌───────────────────────────────┐                  
│┌───────┐    ┌───────────────┐ │     ┌────────┐
││  ssh  │───▶│ epithet proxy │─┼────▶│  host  │
│└───────┘    └───────────────┘ │     └────────┘
└─────────────────────┼─────────┘                  
                      │                            
                      ▼                            
              ┌───────────────┐                    
              │ epithet agent │                    
              └───────────────┘                    
                      │                            
                      ▼                            
              ┌───────────────┐                    
              │      CA       │                    
              └───────────────┘                    
                      │                            
                      ▼                            
              ┌───────────────┐                    
              │ policy server │                    
              └───────────────┘                    
```

Using a proxy lets us send things like the target user and host, so we can arrange for different certs for different hosts, or different users on a host.

Policy server now responds with both the cert params and a policy to apply to the cert, indicating to the agent which hosts the cert should be used for. Returning the policy allows us to decide whether or not to request a new cert by matching the policy to the outgoing ssh request. For example, sshing as `deployer@` can use a generic longer lived cert, but sshing as `root@` will *always* generate a new, 1m TTL cert. It can also thusly support naming schemes: `ssh root@dev324g.example.com` can use a shared cert if it matches a policy like: `host =~ /^dev[.*]\.example\.com$/`. The policy is solely a *certificate matching policy* and does not offer any additional security, but it allows us to reuse certificates more efficiently. Access to prod hosts, `root` (or a user with `sudo` access), etc, can be granted on a host by host basis, and with very short TTL. The very short TTL allows the policy server to do some heuristics, for instance "is the deploy host actually running a deployment?" before granting a cert for an ssh based deploy tool.

## Notes

* Discussion about [using ssh-keygen without files](https://gist.github.com/kraftb/9918106) to avoid needing to muck about with keys
* Use [daemonize](https://github.com/knsd/daemonize/) behind `epithet proxy` to start the agent? Maybe have that as an option anyway.
* Agent probably *is* actually going to be an ssh agent as well, as we need to feed certificates to the ssh process. If we want to avoid writing keys to disk (and we do) we'll need to generate keys and stash them in the agent. We can just have it spin up an SSH_AUTH_SOCK per new connection, and tear it down when the connection ends. Doing so implies we should not `exec` the child ssh from the agent, as we'll want to know when it closes/terminates.
