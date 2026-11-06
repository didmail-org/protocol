# Protocol reference

Status: unreleased working drafts. Audience: protocol implementers and security reviewers. English is authoritative. These documents are not an IETF/ISO standard or an independent cryptographic audit.

## Choose a task

The main reading path is [SDK setup](../../README.md), this contract index, then
[implementation/integration](dmp-1/implementation.md). Select only the relevant
normative/security contracts below; they are different responsibilities, not
successive versions to merge.

| Task | Read |
| --- | --- |
| Implement wire codecs or authenticated HTTP | Base specification, schemas and fixture provenance |
| Integrate bounded transport, confirmation or receiving-key APIs | [SDK integration](dmp-1/implementation.md#sdk-integration-contracts) |
| Change encryption-key transfer files | [Portable archive](device-key-archive.md); account recovery capsule remains separate |
| Authorize wallet spending or recover original tasks | [Payment guards](payment-authorization.md) and [task recovery](task-recovery.md) |
| Change eligibility, visibility or automatic delivery | Member, category and sponsorship contracts below |
| Bind ARC identity to a mailbox or restore an encrypted capsule | [Onboarding](account-onboarding.md) and its schema/vectors |
| Maintain retired ciphertext/wire compatibility | Legacy fixture README and DMP/2 boundary below |

## Active contracts

| Contract                                               | Purpose                                                                   | Implementation/evidence                                                                                  |
| ------------------------------------------------------ | ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| [DMP/1 base specification](dmp-1/specification.md)     | Discovery, authenticated requests, artifacts, encryption and NFT delivery | [SDK source](../../src), [Native ARC protocol handlers](https://github.com/didmail-org/server/tree/main/blocklet/providers/didmail-http/source/protocol)                |
| [Member direct storage](member-mail.md)                | Explicit automatic-delivery extension and offline server receipt          | [Shared vectors](fixtures/member-mail.json), [SDK tests](../../test)                  |
| [Envelope/namecard categories](envelope-categories.md) | Signed member-only visibility, immutable categories and admission         | [Server routes](https://github.com/didmail-org/server/tree/main/blocklet/providers/didmail-http/source/api/src/routes)                                                            |
| [Node-sponsored NFT](member-sponsored-nft.md)          | Zero sender payment with a real node-funded NFT                           | [Native ARC delivery](https://github.com/didmail-org/server/tree/main/blocklet/providers/didmail-http/source/protocol) and SDK conformance tests                                       |
| [Mailbox onboarding](account-onboarding.md)            | Approved associations, signed lookup and optional encrypted recovery      | [Recovery schema](schemas/account-recovery-v1.schema.json), [vectors](fixtures/account-recovery-v1.json) |

The member and sponsored-NFT contracts extend the base draft explicitly. Read them together; base-profile references to a paid envelope do not describe internal member delivery. Existing paid signatures and ciphertext encodings remain unchanged. DMP/1 is the public mail protocol; historical mail send/download routes return `410 PROTOCOL_RETIRED`.

## Local client security contracts

- [Payment authorization](payment-authorization.md): economic guards, explicit consent and original-byte persistence.
- [Task recovery](task-recovery.md): read-only automatic status and narrowly approved original submission.
- [Portable device-key format](device-key-archive.md): signed/password-encrypted cross-client local archive; separate from the account-recovery capsule.

## Schemas and fixtures

[DMP/1 schema](dmp-1/schema.json) and [OpenAPI](dmp-1/openapi.json) document the base profile. The SDK's strict validators, extension documents and cross-language tests define the implemented extension fields; do not assume every base schema models later extensions. [Implementation scope](dmp-1/implementation.md) identifies current limits.

- [RFC 9180 HPKE fixture](dmp-1/fixtures/hpke-rfc9180.json): upstream source provenance is included in the fixture.
- [Account recovery](fixtures/account-recovery-v1.json) and [member mail](fixtures/member-mail.json): shared public compatibility inputs.
- [Legacy attachment vectors](fixtures/legacy-attachments/README.md): retained byte-compatibility inputs for earlier ciphertext.
- [Retired DMP/2 artifacts](dmp-2/README.md): schemas and vectors retained for regression tests only; ordinary/chain-VC delivery is not supported.

Fixture keys and nonces are deliberately public test material. They must never control funded accounts or real mail. Vectors demonstrate selected compatibility properties, not security certification or real-chain settlement.

## Making changes

Preserve signed preimages, exact field sets, canonical encodings and identity derivation unless the task explicitly changes a protocol contract. Update strict validators, schemas where applicable, shared fixtures and all consumers together. Import the complete mobile SDK snapshot through its documented tool; never patch individual vendored files.

See [development](https://github.com/didmail-org/overview/blob/main/docs/development.md), [documentation policy](https://github.com/didmail-org/overview/blob/main/docs/documentation.md) and [release gates](https://github.com/didmail-org/overview/blob/main/docs/status.md).
