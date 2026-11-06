# DMP/1 implementation scope

Status: current implementation map. Audience: maintainers and implementers.

| Layer                | Source and responsibilities                                                                                                                       |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| TypeScript reference | [SDK source](../../../src): canonical artifacts, HPKE, HTTP signatures, strict evidence validators and durable client interfaces |
| Native ARC server | [Protocol handlers](https://github.com/didmail-org/server/tree/main/blocklet/providers/didmail-http/source/protocol), instance AFS persistence, replay/admission checks, immutable terms and asynchronous delivery |
| Extension            | [DMP integration](https://github.com/didmail-org/extension/blob/main/src/libs/dmp.ts), local task journal and inbox synchronization                                          |
| React Native         | [DMP integration](https://github.com/didmail-org/mobile/blob/main/src/utils/dmp.ts), complete SDK snapshot and native encrypted persistence                                  |
| Flutter              | [Independent Dart implementation](https://github.com/didmail-org/desktop/tree/main/lib/core/dmp), SQLCipher journal and shared vectors                                      |

Active extensions are [member direct storage](../member-mail.md), [node-sponsored NFT](../member-sponsored-nft.md), [template categories](../envelope-categories.md) and [account onboarding](../account-onboarding.md). Ordinary/chain-VC delivery is [retired](../dmp-2/README.md).

The server rejects historical public mail send/sign/download routes with `410 PROTOCOL_RETIRED`. Test-only retained adapters protect old ciphertext and signature compatibility without reopening those routes. Contact/namecard recovery is a separate, internal-only integration; it must not be inferred from DMP mail support.

Runtime checks cover malformed artifacts, authorization/replay, binary/Unicode data, restart/fencing and signed-byte preservation. Orphan-object cleanup, deployment acceptance, real-chain interoperability and independent security review remain distinct concerns. See [project status](https://github.com/didmail-org/overview/blob/main/docs/status.md), [server docs](https://github.com/didmail-org/server/blob/main/docs/README.md) and component references for current gates. Automated tests do not broadcast real transactions.

## SDK integration contracts

The following contracts describe the current SDK API and local persistence, not
additional wire formats. Read the base specification and applicable extensions
for exact signed artifacts.

### Chain confirmation and trusted transport

The explicit `arcblock-dolt-ledger/1` confirmation policy uses distinct primary-ledger evidence without a block height; legacy `arcblock-committed` still requires positive block evidence. A client with `expectedChain` must list accepted `confirmationPolicies` to opt into ledger confirmation; the default permits only block confirmation. Accepted quotes remain immutable. `validateReceiptChainEvidence` rejects mixed models/networks and unknown fields/backend versions; these signed service attestations do not independently prove chain consensus.

`inspectDoltCommittedRecord` binds a primary ledger response to SHA-256 of the caller's original signed bytes and the configured network/backend. The caller must independently authenticate and authorize those bytes and trust the configured RPC transport. It returns `pending` only for an explicit null record, distinguishes a persisted execution failure, and rejects malformed evidence. It does not verify signatures, fabricate a block height, establish block consensus or enable a payment policy on its own. The shared `test/fixtures/dolt-ledger.json` vectors document its acceptance boundaries. This draft's offline conformance is not proof of real-chain payment/mint interoperability or production readiness.


### Bounded response transport

`Transport` accepts an optional fifth argument, `{maxResponseBytes}`. The default
and maximum are 16 MiB of decoded response bytes; a caller may lower the limit
to any safe nonnegative integer, including zero. Blob downloads pass each
authenticated chunk's exact ciphertext length, and account-link requests use
140,000 bytes. A transport must enforce the bound before buffering a complete
response. The SDK also checks returned lengths to reject a nonconforming custom
transport, but that check cannot undo allocations already made by that transport.

The default browser/standards `fetchTransport` reads a stream incrementally,
counts decoded bytes even with absent or false Content-Length, and cancels an
oversized body without waiting for the server to finish. Compression overhead
does not reject otherwise valid decoded chunks. A fetch implementation without
streaming support must provide a bounded native transport; it cannot fall back to
an unbounded `arrayBuffer()`. React Native enforces the same local byte budget in
its native networking boundary before passing data to JavaScript. Limits are
transport metadata, not HTTP signature inputs or service-provided permissions.

### Device encryption key archives

`DmpClient` accepts an optional `EncryptionKeyStore` and exposes explicit
`rotateKey()`. A store must atomically save independent copies of the signed
public record and its random 32-byte X25519 secret, reject immutable conflicts,
and return caller-owned private-key copies. The SDK reads the durable pair back
before making any registration request. `ownKey()` retries publication of that
exact archived record after restart, verifies exact lookup/registration replies,
and fails closed for expiry, revocation or a missing private key. Rotation retains
old records and does not automatically revoke them.

`blob()`/`document()` resolve archived keys by the authenticated envelope key ID;
legacy wallet-derived messages remain readable. Backups must preserve the union
of all private keys and revocations, and account changes must cancel pending key
operations. Providing a memory store does not satisfy production durability.
Native archive storage, restore integration and rotation UI must be completed
before a client enables this feature for users. Neither this API nor its tests
prove cross-device private-key distribution or hosted service operation.

`ensureReceivingKey()` checks the newest authenticated active registry record
(createdAt descending, then keyId ascending) and verifies its exact archived
record/private pair or the legacy wallet-derived private key. A known registry
with missing, expired or unavailable keys never triggers an implicit primary-key
replacement. Only a genuinely empty registry may bootstrap and then recheck its
advertisement. Inbox receiving setup and `create()` use this check; `ownKey()`
remains the lower-level publication/retry API for explicit recovery workflows.
A selected service's omission of an entirely unseen key is still a freshness
trust boundary, not a transparency guarantee.

`checkReceivingKey()` provides the same authenticated selection/private-key check
without publication: `ready` and `import_required` include the selected public
record; `unregistered` means the registry is empty; `no_active_key` means it has
no eligible current record. Malformed registries, immutable conflicts and corrupt
local key material still reject. It never calls `ownKey()` or issues a key PUT.
It may remember verified signed revocations locally. Callers must bind results to
the captured account, selected node and page lifetime, and present them as an
observation of that node at check time, not a delivery or future-readiness proof.

An `EncryptionKeyStore` may implement `lookup(keyId)` to return one authenticated
`{record, secret}` pair without enumerating history. The private bytes must be a
fresh caller-owned copy, and absence is authoritative. The client checks exact
record equality and private-key binding and erases returned bytes after use or
failure. Receiving checks, rotation readback and historical blob access use this
capability; older stores without it retain the enumeration path. A lookup error
or conflict never falls back to a scan or alternate key. `ownKey()` still lists
records to choose a publication/retry candidate, and full archive export/backup
validation must still inspect history. Indexed access authenticates the requested
pair, not the integrity of every unrelated historic entry; it does not change
key record, encryption, revocation or backup wire formats.

`publishKey(keyId)` explicitly registers one selected archived public record.
It verifies that record's current validity, owner/key ID and durable private key
before HTTP, erases temporary private bytes, and retries the exact immutable
record after response loss. A newer local key never changes this target. Missing,
expired, corrupt or mismatched selected entries fail without generating another
key or falling back to `ownKey()`. Applications must show the account, node and
key ID for consent, then check which key the node currently selects: accepting a
public record does not imply that it became primary. Public registration can
have completed when a network error/cancellation is reported; retain the private
archive and query before retrying. This API does not revoke previous keys.

`revokeKey(record, reason)` explicitly signs an irreversible local revocation and
publishes it. It requires a durable `RevocationStore`, verifies the own public
record (expired history is allowed), saves and reads back the exact signed intent
before HTTP, then checks both the POST acknowledgment and public key-by-ID
readback. It never needs or deletes the corresponding encryption private key.
A fresh-client retry reuses the same timestamp, reason and signature; a different
reason conflicts with the immutable local intent. Only authenticated request
nonces change. Invalid/missing persistence fails before dispatch.

Signing the intent immediately disables new use locally even when publication
fails or the key is absent from this node. Export/backup preserves that signed
fact. A successful local save is not remote acknowledgment; callers must expose
uncertain publication and offer retry of this same intent. Historic delivered
ciphertext remains readable with retained private material. UI confirmation must
explain these irreversible/local-versus-node boundaries before calling the API.
