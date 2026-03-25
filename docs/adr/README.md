# Architecture decision records

This directory contains architecture decision records (ADRs) for epithet. ADRs document significant design choices, the reasoning behind them, and their consequences. The goal is to prevent relitigating settled questions while preserving the context that informed each decision.

## Format

Each ADR follows this structure:

```markdown
# NNN: title in sentence case

**Status:** draft | accepted | superseded by [NNN](NNN-title.md)

## Context

What situation or problem prompted this decision? What constraints or forces were at play?

## Decision

What was decided, stated plainly.

## Consequences

What does this decision make easier or harder? What is explicitly deferred or out of scope?

## Open questions

What remains unresolved and may prompt a future ADR?
```

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-ca-policy-server-separation.md) | CA and policy server separation | Draft |
| [0002](0002-token-validator-plugin-mechanism.md) | Token validator plugin mechanism | Draft |
