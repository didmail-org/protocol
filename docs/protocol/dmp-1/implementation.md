# DMP/1 implementation scope

Status: current implementation map. Audience: maintainers and implementers.

| Layer                | Source and responsibilities                                                                                                                       |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| TypeScript reference | [SDK](../../../README.md): canonical artifacts, HPKE, HTTP signatures, strict evidence validators and durable client interfaces |
| Worker               | [DMP API](https://github.com/didmail-org/server/blob/main/workers/dmp-api.ts), D1/R2 storage, replay/admission checks, quotas, immutable terms and asynchronous delivery          |
| Extension            | [DMP integration](https://github.com/didmail-org/extension/blob/main/src/libs/dmp.ts), local task journal and inbox synchronization                                          |
| React Native         | [DMP integration](https://github.com/didmail-org/mobile/blob/main/src/utils/dmp.ts), complete SDK snapshot and native encrypted persistence                                  |
| Flutter              | [Independent Dart implementation](https://github.com/didmail-org/desktop/tree/main/lib/core/dmp), SQLCipher journal and shared vectors                                      |

Active extensions are [member direct storage](../member-mail.md), [node-sponsored NFT](../member-sponsored-nft.md), [template categories](../envelope-categories.md) and [account onboarding](../account-onboarding.md). Ordinary/chain-VC delivery is [retired](../dmp-2/README.md).

The Worker rejects historical public mail send/sign/download routes with `410 PROTOCOL_RETIRED`. Test-only retained adapters protect old ciphertext and signature compatibility without reopening those routes. Contact/namecard recovery is a separate, internal-only integration; it must not be inferred from DMP mail support.

Runtime checks cover malformed artifacts, authorization/replay, binary/Unicode data, restart/fencing and signed-byte preservation. Orphan-object cleanup, deployment acceptance, real-chain interoperability and independent security review remain distinct concerns. See [project status](https://github.com/didmail-org/didmail/blob/main/docs/status.md), [server docs](https://github.com/didmail-org/server/blob/main/docs/README.md) and component references for current gates. Automated tests do not broadcast real transactions.
