---
yatl_version: 1
title: Extract inventory into a separately deployable service
id: a5qt7g3m
created: 2026-09-04T16:14:44.934795Z
updated: 2026-09-04T16:15:25.300751Z
author: Brian McCallister
priority: critical
tags:
- inventory
- security
- architecture
- host-enrollment
---

Extract inventory from the policy server as a logical service boundary so the policy engine can remain private and accept requests only from authenticated CA instances. Preserve one-command deployment through `epithet server`; separate deployability must not force small installations to operate three independent units.

Responsibilities and trust boundaries:
- The CA is the narrow public certificate-issuance and bootstrap surface. It owns the signing key, calls policy over an authenticated private channel, and validates the bounded certificate parameters returned by policy.
- The policy service compiles and evaluates Writ and hosts require/when/notify plugins. It has no public listener, no CA private key, and no inventory write credentials. Treat request fields as transitively attacker-controlled even though the CA is its only network caller.
- The inventory service owns user and host facts, lifecycle, source provenance, and the authorization read projection. Policy receives only read access.
- Expose host enrollment, SCIM provisioning, infrastructure registration, administration, and policy resolution as separately authenticated capabilities. Permit separate listeners/resource pools so public enrollment traffic cannot starve authorization reads.

Resolver contract:
- Define a versioned inventory protocol independent of Writ and any database schema.
- Resolve the authenticated identity and requested host together so user, membership, host labels/accounts, host ID, and principal-mode metadata come from one consistent snapshot.
- Preserve the distinction between an absent entity (structural denial) and a resolver/storage failure (retryable 5xx that fails closed).
- Return an inventory revision plus observed-at/freshness information sufficient to enforce and audit an explicit stale-read policy.
- Keep the Writ-facing host projection separate from certificate-issuance metadata, and bound request/response sizes and latency.
- Authenticate policy readers with Unix-socket permissions for local composition and workload identity or mTLS for distributed deployment.

Implementations and configuration:
- Retain static YAML as the simplest implementation. It may run in-process behind the resolver interface or through a small inventory server; static deployments advertise no writable enrollment capability.
- Add an HTTP inventory client/server implementation as the interoperable adapter boundary for managed SCIM inventory and third-party integrations.
- If SQL backends are added, terminate them in the inventory component rather than giving policy schema, migration, or write responsibilities. Keep two ownership models explicit: either Epithet privately owns and migrates its schema and all writers use inventory APIs, or an operator owns a documented read-only relational projection. Do not promise arbitrary direct writers against an Epithet-managed schema.
- Leave PostgreSQL/MySQL backend selection until after the resolver semantics are fixed; HTTP is the universal extension mechanism.

Host discovery and integrations:
- Keep `--ca-url` as the only host bootstrap location. The CA conditionally advertises one or more capability-specific inventory host-enrollment URLs; it never advertises or proxies the policy API.
- Prospective hosts may access only enrollment operations, not inventory enumeration or policy resolution.
- Consul, Kubernetes, cloud, and configuration-management integrations submit authenticated, source-scoped assertions. Host identity or self-registration is evidence, not admission authority; activation and security-sensitive labels require the configured admission authority.
- Preserve default-closed, bounded enrollment windows and short-lived scoped tokens from the existing host-enrollment tasks.

Deployment and easy path:
- Keep `epithet server` as the supported composition root. It owns configuration, discovery wiring, health, logging, startup, and shutdown while preserving component interfaces and private channels.
- In the static easy path, do not require a separately operated inventory service.
- In a managed all-in-one mode, the supervisor may run CA, policy, and inventory as child processes connected by Unix sockets. Document that same-user subprocesses provide network isolation but not the strongest CA-key isolation.
- Support independently deployed CA, policy, and inventory services without changing protocol semantics.
- Preserve the five-minute first-success goal: a small organization should be able to start one Epithet unit, enroll a host from the CA URL, authenticate, and obtain a short-lived destination-bound SSH certificate without deploying a database or understanding the internal topology.

Implementation sequence:
1. Record the component and trust-boundary ADR, including deployment profiles and threat assumptions.
2. Specify the versioned resolver request, response, errors, revision, and freshness semantics.
3. Refactor the in-process inventory interface to support one consistent request snapshot and adapt static inventory without changing authorization behavior.
4. Implement and test the bounded authenticated HTTP resolver server/client.
5. Add the separately runnable inventory command and policy inventory-source configuration.
6. Update `epithet server` composition so policy is never publicly routed and managed enrollment links name the inventory service.
7. Split policy checking from inventory validation where needed and include policy content ID plus inventory revision in decision/audit records.
8. Rebase the existing managed enrollment, host registry, and discovery tasks onto the inventory boundary before implementing database or SCIM storage.

Acceptance:
- External clients cannot route to policy through either the CA or inventory service; only authenticated CA instances can invoke policy decisions.
- A policy process or arbitrary policy plugin has neither the CA private key nor inventory mutation authority in the separated deployment profile.
- Static local, managed all-in-one, and independently deployed inventory modes pass the same resolver conformance tests and produce equivalent authorization decisions.
- Each evaluation observes one coherent inventory revision; missing records and infrastructure failures retain their distinct fail-closed behavior.
- Managed CA discovery advertises only capability-specific inventory enrollment endpoints; static deployments omit them.
- Public enrollment load cannot consume the resources reserved for policy-resolution reads.
- `epithet server` remains a documented, supported one-command path rather than a development-only wrapper.

---
# Log: 2026-09-04T16:14:44Z Brian McCallister

Created task.
