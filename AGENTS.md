# DIDMail Protocol

This repository is the canonical TypeScript protocol SDK and protocol documentation. Use Node.js 24.14 or newer and pnpm 12.11.2. Run `pnpm install --frozen-lockfile`, `pnpm type-check`, `pnpm build` and `pnpm test` for changes. Preserve LICENSE, NOTICE, THIRD_PARTY_NOTICES and vector provenance.

Do not change chain identity derivation, signature preimages, encodings, encryption or payment semantics during structural work. Fixtures are public compatibility inputs, not cryptographic certification. Do not put credentials, private keys, mnemonics, real mail, local databases, logs or build artifacts in Git. Do not broadcast chain transactions or send external messages from automated tests.

The mobile repository maintains a complete hash-verified SDK snapshot. Coordinate deliberate SDK changes with consumers and import the complete snapshot through the mobile repository's documented workflow. Engineering documentation is in English. Mark unresolved security and deployment limitations accurately.
