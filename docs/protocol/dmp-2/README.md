# Retired ordinary-mail artifacts

Status: retired on 2026-10-30. Audience: maintainers of compatibility tests.

DMP/2 ordinary/chain-VC delivery is not supported or advertised by the current mail service. Do not enable old flags or interpret these files as deployment instructions. Current internal free mail uses the explicit [DMP/1 member direct-storage extension](../member-mail.md).

The following files remain at stable paths because SDK and server regression suites consume them:

- [schema.json](schema.json) and [openapi.json](openapi.json): independent historical artifact contracts.
- [compact-vc-wire.schema.json](compact-vc-wire.schema.json): historical compact tuple validation.
- [fixtures](fixtures/): public free/paid/compact compatibility vectors.

The obsolete product proposal and implementation diary have been removed. Git history retains their design context. These retained test artifacts do not imply public endpoints, compatible inbox reading or a production capability. See [protocol index](../README.md).
