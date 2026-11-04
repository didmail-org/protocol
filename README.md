# @didmail/protocol — DMP/1 reference SDK

> Updated same-node members can use direct storage without envelope, payment, mail NFT or on-chain notification. See the [member-mail contract](docs/protocol/member-mail.md). Older clients and external delivery retain the applicable NFT rules.

Unreleased working draft. Normative specification: `docs/protocol/dmp-1/specification.md`. Not an international standard, a cryptographic audit or a production-readiness certification.

Build this package before building consumers: `pnpm install && pnpm build && pnpm test`.
The server and clients consume a versioned SDK. React Native maintains a complete, hash-verified SDK snapshot; update it only through its import workflow. ESM and CommonJS builds contain bundled portable cryptographic primitives; native applications must provide a secure `crypto.getRandomValues` implementation. No Node-only cryptography is required by the SDK.

The SDK provides strict canonical JSON, RFC 9421 request signing, RFC 9180 HPKE, AES-256-GCM chunk encryption, signed manifests/key records/quotes/receipts, and an authenticated client with a required durable task-store interface. An application must provide the ArcBlock identity derivation matcher, selected-chain policy, service-key pinning, transaction signing and an encrypted local task journal. Never put private keys or plaintext into a server task.

The explicit `arcblock-dolt-ledger/1` confirmation policy uses distinct primary-ledger evidence without a block height; legacy `arcblock-committed` still requires positive block evidence. A client with `expectedChain` must list accepted `confirmationPolicies` to opt into ledger confirmation; the default permits only block confirmation. Accepted quotes remain immutable. `validateReceiptChainEvidence` rejects mixed models/networks and unknown fields/backend versions; these signed service attestations do not independently prove chain consensus.

`inspectDoltCommittedRecord` binds a primary ledger response to SHA-256 of the caller's original signed bytes and the configured network/backend. The caller must independently authenticate and authorize those bytes and trust the configured RPC transport. It returns `pending` only for an explicit null record, distinguishes a persisted execution failure, and rejects malformed evidence. It does not verify signatures, fabricate a block height, establish block consensus or enable a payment policy on its own. The shared `test/fixtures/dolt-ledger.json` vectors document its acceptance boundaries. This draft's offline conformance is not proof of real-chain payment/mint interoperability or production readiness.

Official HPKE vectors are sourced from the CFRG repository, with the source URL stored next to the fixture. Build artifacts under `dist/` are generated, not hand edited. Run the conformance suite after changing any serialization, signature preimage, KDF label or byte encoding. Cross-language fixtures are normative test inputs, not a substitute for independent security review.

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

## License

DIDMail original code and documentation use [Apache-2.0](LICENSE). See [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES); bundled third-party components retain their original licenses.
