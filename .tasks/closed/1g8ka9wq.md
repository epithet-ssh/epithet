---
yatl_version: 1
title: 'Security: OIDC validator skips audience check when client_id empty'
id: 1g8ka9wq
created: 2026-06-23T16:52:29.960526897Z
updated: 2026-08-14T15:47:02.854082Z
author: Brian McCallister
priority: medium
tags:
- security
- policyserver
---

OIDC validator silently disables audience check when ClientID is empty.

Severity: MEDIUM (library footgun; not exploitable in the default server config)

Location: pkg/policyserver/oidc/validator.go:83-88

  if config.ClientID != "" {
      verifierConfig.ClientID = config.ClientID
  } else {
      verifierConfig.SkipClientIDCheck = true   // accepts ANY audience
  }

With an empty ClientID, any token signed by the issuer is accepted regardless of its aud claim. Against a shared IdP (e.g. Google) an ID token minted for a DIFFERENT OAuth client at the same issuer would validate -> authentication bypass via token reuse. SkipExpiryCheck is similarly exposed on the Config.

Why it is not currently exploitable end-to-end: ServerConfig.Validate() and PolicyRulesConfig.Validate() (pkg/policyserver/policy_config.go:38,134) require oidc.client_id, and the evaluator always passes it (pkg/policyserver/evaluator/evaluator.go:35,52). But the Validator is exported and enforces nothing itself; any other caller or future refactor silently loses audience binding.

Fix: make NewValidator reject an empty ClientID (or require an explicit SkipClientIDCheck opt-in field) rather than silently degrading. Consider the same for SkipExpiryCheck.

---
# Log: 2026-06-23T16:52:29Z Brian McCallister

Created task.

---
# Log: 2026-08-14T15:47:02Z Brian McCallister

Closed: Fixed in task 4 of oidc-only-auth-plan: NewValidator now rejects empty ClientID, and SkipExpiryCheck/SkipClientIDCheck were deleted entirely along with the TokenValidator interface.
