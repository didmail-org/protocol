# Portable device-key archive format

Status: implemented cross-client local format, version 1. Audience: Dart/TypeScript implementers. This is not a chain transaction or an independently audited standard.

## Format and bounds

The canonical outer JSON has exactly `format`, `version`, `ownerId`, `encrypted`. `format=didmail-device-keys`, integer `version=1`; UTF-8 input is limited to 16 MiB. Validate identity/fields/version/size before password derivation. Reject duplicate JSON names, old CryptoJS/CBC payloads, unknown algorithm fields and caller-selected KDF iteration counts.

The inner signed object is `{version:1,ownerId,keys,revocations,proof}`, using Ed25519 canonical JSON domain `DMP1-DEVICE-KEY-ARCHIVE`. Each key entry has exactly `record` and canonical-base64url `privateKey` (32-byte X25519 secret). Verify the same owner, historic-valid signed public record, exact private binding and unique key ID. Retain expired/revoked keys for historical reading, not new receiving.

Verify each own/contact signed revocation and deduplicate by owner/key. The enclosing identity signature binds the complete archive; knowing its password cannot authorize altered facts. A valid signature does not establish freshness. Limits are 1024 key entries, 8192 revocations and 12 MiB plaintext; reject excess rather than truncate.

Encryption uses `didmail:sealed:2:`: PBKDF2-HMAC-SHA256 with 600000 iterations, 32-byte derived key, random 16-byte salt and NaCl SecretBox XSalsa20-Poly1305 with random 24-byte nonce. KDF scope is `didmail:sealed:2\0device-key-archive:1:<ownerId>\0`, combined with the salt. Canonical base64 carries `salt || nonce || tag || ciphertext`. Passwords use exact UTF-8 without Unicode normalization, at least 12 Unicode characters and at most 1024 UTF-8 bytes. Deliver the password separately from the file.

## Import/export and provenance

No wallet signing secret, mnemonic, mail body or payment task is included. Import depends on account/file/password, not the currently selected node. Prevalidate archive/local signatures, exact secrets and immutable conflicts. SQLCipher imports are transactional and union-merge keys/revocations; old files never remove newer facts. React Native's KV implementation saves/rechecks revocations first and can report retryable partial progress rather than falsely claim rollback.

Export captures owner and list snapshots before asynchronous work. File operations use bounded reads and captured account/lifetime scope. Compare exact secret bytes even if X25519 clamping produces equal public keys. Hardware/VM memory wiping and frame-rate guarantees are outside this format.

Remember file provenance using the actual encrypted-file SHA-256 (`device-key-archive:sha256:<digest>` in Flutter). It is a local source label, not a DMP endpoint or proof of current receiving eligibility. The mobile equivalent preserves its strict source metadata across backup merges. Authenticated revocation facts remain useful across node contexts.

## Readiness and evidence

After transfer, perform a read-only node receiving check to verify the selected authenticated public record and matching local secret at that time. Do not publish a replacement key implicitly. Missing/expired/revoked keys and source failures remain distinct. The node can still omit an entirely unseen key; no transparency log exists.

Cross-language tests use actual Dart/TypeScript codecs and isolated native iOS/macOS file/storage flows. They validate selected compatibility and restore properties, not the full user-driven cross-device/physical-device workflow. Sources: [Flutter transfer service](https://github.com/didmail-org/desktop/blob/main/lib/domain/services/device_key_transfer.dart), [mobile archive reference](https://github.com/didmail-org/mobile/blob/main/docs/device-key-archive.md) and [Flutter acceptance guide](https://github.com/didmail-org/desktop/blob/main/docs/desktop-ui-acceptance.md).
