# Mapping OIDC identities to SCIM users

Research recorded on 2026-10-14. These findings come from provider documentation
and source inspection, not live interoperability tests. This records provider
research and the resulting identity-boundary decision. The directory README
documents the implemented configuration interface.

## Identity model under discussion

Select an OIDC claim and a SCIM attribute whose values identify the same person
within the configured identity source. Map both to Epithet's user identity used
for directory lookup. The selected value must identify one user in that scope.

The authentication identity and SCIM resource `id` are conceptually distinct,
but may share one value when the selected identity meets SCIM's stability,
uniqueness and non-reassignment requirements. Epithet assigns that value before
calling storage; the SCIM client-supplied read-only `id` is ignored.

SCIM `externalId` is often a suitable carrier because an integration deliberately
puts the matching upstream identity there. The field name alone does not establish
that it matches an OIDC claim, is present, or is unique. We must not assume that
every SCIM provider's `externalId` is an authentication identity.

## Provider findings

| Provider | Mapping and evidence | Qualification |
|---|---|---|
| **PingOne** | OIDC `sub` defaults to PingOne `user.id`. Configure outbound SCIM to carry the same user ID in `externalId`. [OIDC mappings](https://developer.pingidentity.com/pingone-api/platform/applications/application-attribute-mapping/index.html), [provisioning mappings](https://docs.pingidentity.com/pingone/integrations/p1_provisioning.html) | Proposed recipe based on configurable mappings; not a verified default for every connector. |
| **PingFederate** | Configure a stable source-directory identifier into an OIDC claim and SCIM `externalId`. [OIDC attribute contract](https://docs.pingidentity.com/pingfederate/13.0/introduction_to_pingfederate/pf_attr_contract.html), [outbound SCIM attributes](https://docs.pingidentity.com/integrations/scim/setup/pf_scim_connector_supported_attributes_reference.html) | The appropriate identifier depends on the backing directory. There is no single provider-wide default recipe. |
| **Keycloak** | With its ordinary subject mapping, use the Keycloak user ID. The third-party `keycloak-scim-outbound` extension explicitly sends that ID as SCIM `externalId`. [Keycloak documentation](https://www.keycloak.org/docs/26.8.1/server_admin/), [outbound extension](https://github.com/TerminSolutions/keycloak-scim-outbound) | Connector-specific evidence, not an endorsement or interoperability test of the extension. Pairwise or customized subjects require corresponding mapping changes. Keycloak's built-in SCIM API provisions into Keycloak; it does not itself provide this outbound flow. |
| **Microsoft Entra ID** | Use OIDC `oid`, and configure SCIM `externalId` from Entra `objectId`. Both refer to the same directory object within the tenant. [Token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference), [provisioning attribute configuration](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/customize-application-attributes) | Entra `sub` is application-specific. Keep tenant scope with the identity; the same person can have different object IDs in different tenants. |
| **Okta** | The ordinary ID-token `sub` is the Okta user ID, which SCIM provisioning can send as `externalId`. [OIDC claims](https://developer.okta.com/docs/api/openapi/okta-oauth/guides/overview), [SCIM requests](https://developer.okta.com/docs/api/openapi/okta-scim/guides/scim-20) | Confirm the connector's mapping and any customized subject configuration. |
| **OneLogin** | OIDC `sub` is the OneLogin user ID. Configure the SCIM template's `externalId` from `$user.id`. [OIDC UserInfo](https://developers.onelogin.com/docs/openid-connect/api/user-info/), [SCIM templates](https://developers.onelogin.com/docs/scim/define-user-schema/) | Explicit template configuration, not an assumption about a connector's default payload. |
| **authentik** | Its documentation explicitly states that the default OIDC subject and SCIM `externalId` match, using its hashed user ID. [SCIM provider](https://docs.goauthentik.io/add-secure-apps/providers/scim/) | Other subject modes require corresponding SCIM mappings. |
| **Pocket ID** | OIDC `sub` is its user ID; outbound SCIM source assigns the same `user.ID` to `externalId`. [Claims](https://pocket-id.org/docs/guides/scopes-and-claims), [SCIM implementation](https://github.com/pocket-id/pocket-id/blob/main/backend/internal/scimsync/service.go) | Source-inspected mapping. The source link tracks `main`, so it can change after this research date. |

## Providers with unresolved details

### JumpCloud

The [custom SCIM documentation](https://jumpcloud.com/support/provision-and-manage-users-and-groups-in-apps-using-custom-scim-identity-management-integration)
contradicts itself: it says user `externalId` is not sent, but its mapping table
includes an expression deriving it from `jcUser.id`. Its
[OIDC documentation](https://www.jumpcloud.com/support/sso-with-oidc) identifies
JumpCloud User ID as the default subject.

The common identifier appears available, but the outbound SCIM behavior needs
testing before we can publish a reliable recipe.

### Auth0

Auth0 announced an editable outbound SCIM Action template for Event Streams in
July 2026. This provides a way to configure a common identifier, but the exact
default identity mapping was not verified. Older claims that Auth0 only supports
inbound SCIM are no longer sufficient descriptions of its capabilities.
See the [release announcement](https://auth0.com/changelog?version=v202545).

### Google Workspace

Google's documented automatic provisioning is tied to supported application
connectors. This research did not establish a generic outbound SCIM recipe for
Epithet. That is a provisioning integration gap, not evidence that matching
identities is inherently impossible.
See [automated user provisioning](https://knowledge.workspace.google.com/admin/users/advanced/about-automated-user-provisioning).

## Design implication

The evidence supports selecting a claim and a SCIM attribute per identity-source
integration. Several providers already expose matching values; others allow
administrators to configure them. It does not support universally equating OIDC
`sub`, SCIM `externalId`, or SCIM resource `id`.

The agreed implementation uses one stored user ID for SCIM addressing and fact
lookup. The adapter selects the source attribute through
`scim-user-id-attribute`, defaulting to `externalId`; storage does not select or
map fields. See [directory configuration](../pkg/facts/directory/README.md#scim-identity-configuration)
for supported fields and current behavior.

Identity mapping alone does not establish complete SCIM interoperability. Actual
connector request patterns and lifecycle behavior still need testing against
Epithet.
