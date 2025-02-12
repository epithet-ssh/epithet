# Open TODO Items

1. Get rid of the hooks machinery, replace with less abstraction.
2. Make our agent implement Agent and ExtendedAgent and be served directly. It should keep a keyring which it proxies requests to. This will allow us to intercept `Sign` requests to ensure that the certificate is still valid, and invoke our auth muckery if it needs to be refreshed.
3. Package up CA to serve on cloud run and/or lambda
4. Make a usable-out-of-box policy server to give folks the 15 minute demo experience.
