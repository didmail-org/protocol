# @didmail/protocol — DMP/1 reference SDK

Canonical TypeScript SDK and protocol contracts for DIDMail. This is an unreleased
working draft, not an international standard, cryptographic audit or production
certification. English is authoritative.

## Reading paths

Use this guide for SDK setup, the [task index](docs/protocol/README.md) to select
contracts, and [SDK integration](docs/protocol/dmp-1/implementation.md) for runtime,
transport, receiving-key, archive and confirmation requirements. The
[DMP/1 specification](docs/protocol/dmp-1/specification.md) remains normative for
the base wire profile; explicit extension/security contracts have separate scopes.

## Build and verify

Use Node.js 24.14 or newer and pnpm 12.11.2 from this repository:

```sh
corepack pnpm install --frozen-lockfile
pnpm type-check
pnpm build
pnpm test
```

Installation's `prepare` builds declarations plus bundled ESM/CommonJS artifacts.
CI installs the frozen lockfile and runs type-check/tests. Do not hand-edit
`dist/`. Changes to serialization, signature preimages, KDF labels or encodings
require the existing conformance suite and coordinated consumer validation.

Server and clients consume pinned versions. React Native owns a complete,
hash-verified snapshot: use its documented whole-SDK import workflow, never patch
individual snapshot files. This documentation change does not update that snapshot.

## Application responsibilities

The SDK supplies canonical JSON, HTTP signatures, HPKE/chunk encryption and an
authenticated client. Applications supply secure `crypto.getRandomValues`,
ArcBlock identity matching, selected-chain/confirmation policy, service-key pinning,
transaction signing and encrypted durable task/key storage. Memory stores do not
establish production durability. Never put private keys or plaintext into server
tasks; response loss is not authority to replace payment evidence.

[Member direct storage](docs/protocol/member-mail.md) omits envelope, payment,
NFT and chain notification for eligible same-node members. External and older
compatible NFT delivery follow their explicit contracts. Legacy ordinary/chain-VC
artifacts remain test compatibility inputs, not a supported send mode.

Public fixtures, including upstream HPKE vectors with preserved provenance,
establish selected compatibility rather than independent security or real-chain
settlement. Keep original signatures, keys and economic semantics unchanged during
structural work; automated tests must not broadcast transactions or send real mail.

## License

Original code/documentation use [Apache-2.0](LICENSE). Preserve [NOTICE](NOTICE),
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES) and fixture provenance. Bundled third-party
components retain their original licenses.
