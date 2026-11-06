# ARC mailbox association and encrypted recovery — draft v1

This optional application capability is independent of DMP/1 message signatures, HPKE, payment semantics and chain identity derivation. Its implementation contract and HTTP table are in [the server guide](https://github.com/didmail-org/server/blob/main/docs/arc-mailbox-onboarding.md) and the HTTP table below. It does not turn a Passkey credential into an Ed25519 seed.

## Ownership and authorization

ARC verifies login identity A. A mail client creates or selects locally held signing identity B. A approves a device intent in the browser; B signs the complete immutable approval with domain `DIDMAIL-ACCOUNT-LINK/1`. An association is scoped to one service and fixed authorization origin. The service never receives a plaintext signing seed, private device encryption key, backup password, Passkey secret or exported browser session.

One A has one primary B; one B has one A on a node. Unique constraints and tombstones prevent replacement by concurrent enrollment or revocation. Changing the primary mailbox is not supported by this version. Revoke/reactivate requires a new approval and the same original B. Revocation erases the node's recovery ciphertext and increments the association revision, retaining the association for deny enforcement and audit.

`AccountLinkStatement` is the exact wire structure. It binds version, operation, intentId, challenge, origin, serviceId, clientId/public key, arcId, mailboxId/public key, PKCE S256 challenge, expiresAt, revision and recoveryDigest. Clients validate every local binding before signing. The browser displays a code matching the client; approval is explicit, same-origin and CSRF protected. The verifier is a 32-byte random base64url value, never a URL parameter. Intent lifetime is ten minutes.

Every retry creates a fresh DMP HTTP nonce. The intent ID and completion payload remain unchanged. Completion retries return the same result until expiry, provided its association revision still matches; changed payload, backup, association or revocation produces a conflict. Pending client state must be encrypted and durable before network writes. Clear it after the account and local association metadata are safely committed (and any explicitly requested recovery copy is saved), or by explicit cancellation.

Active non-guest ARC membership is required for linking/reactivating. Actual internal/external delivery and applicable sender/node staking requirements follow the [member direct-storage](member-mail.md) and [node-sponsored NFT](member-sponsored-nft.md) contracts; association alone does not establish them. **Recovery and revocation require authentication as the originally linked ARC identity, rather than current sending membership.** Removing a member therefore does not revoke previously owned mail or prevent password-protected recovery. A revoked binding has no online backup; use an offline file. An upstream identity provider that no longer permits that identity to authenticate may also require offline recovery.

Sending authorization is checked against the authoritative member source on each operation; there is no permanent member cache. The database write also checks the local policy revision, association revision and deny entries on A and B. An external membership change cannot be atomically committed with the local AFS transaction: it is observed at the next authoritative check, whereas local deny/binding edits serialize at the database boundary. Unaccepted terms must be refreshed when the calculated fee changes in either direction. Accepted terms and historical signed downloads remain unchanged.

## Recovery capsule

The exact envelope is `AccountRecoveryCapsule` in the SDK and [JSON schema](./schemas/account-recovery-v1.schema.json). JSON files exported by clients are canonical JSON. All binary fields use canonical base64url without padding. The `ciphertext` value encodes AES-GCM ciphertext followed by its 16-byte authentication tag.

Parameters are fixed: PBKDF2-HMAC-SHA256, 600000 iterations, 32-byte derived key, random 16-byte salt, random 12-byte nonce, AES-256-GCM. The domain is the UTF-8 string `DIDMAIL-ACCOUNT-RECOVERY/1` followed by one LF byte (0x0a). The KDF salt is domain bytes followed by the salt. AAD is domain bytes followed by canonical JSON of all envelope fields except ciphertext. Do not reuse this cipher or domain for wire mail encryption.

Passwords use valid Unicode UTF-8 without normalization, nonempty and at most 1024 bytes; new accounts follow their client’s existing registration password policy, while existing-account binding and recovery accept the original password. An envelope must not select arbitrary work factors. Maximum encoded envelope is 131072 bytes, plaintext 65536 bytes, 64 private device keys and 256 own-key revocation facts. Exceeding a bound fails the entire export; do not silently drop old keys. Use the existing full device-key archive/full backup when the minimum capsule is too small.

Plaintext exact fields: `{version:1,mailboxId,seed,keys,revocations}`. Seed is 32 bytes. Each keys item has exactly `{record,privateKey}`, including the original signed KeyRecord and its 32-byte X25519 secret. Clients validate seed→B, every public-record signature/owner/private-key binding, unique key IDs and all own-key revocation signatures before persisting anything. Expired history is retained and validated at its creation time. Cached records about other mailboxes are outside this minimal recovery profile.

A seed alone cannot recover random historical device keys. Export them from the original client's local archive, not from an assumed node archive. This capsule restores mail identity and decryption keys; full client backups remain necessary for downloaded mail, contacts and pending send tasks. Keep a separate offline encrypted file. The node can neither reset its password nor decrypt it.

The extension and Flutter commit the account and key archive in a database transaction. React Native KV storage instead preflights every entry and durably verifies monotonic immutable key writes before publishing the new account; a native write failure can leave verified, unreachable key entries. Its encrypted intent/file remains the recovery journal. Retry adds only missing entries and never substitutes a new mailbox. This is recoverable publication, not a claim of cross-key KV atomicity.

[The public fixture](./fixtures/account-recovery-v1.json) contains a deliberately public test seed and password. Never fund it or use it for real mail. SDK, mobile and independent Dart tests use it; it is not cryptographic certification.

## Availability

The capability is disabled unless explicitly configured with the fixed authorization origin and a trusted `ARC_MEMBERS` source. The implemented beta.74 team-list adapter verifies both instance role and authoritative `approved` state; detail-only or role-only data is insufficient. See the [source contract](https://github.com/didmail-org/server/blob/main/docs/arc-members-source-compatibility.md). Configuration and upstream compatibility must be verified per deployment; fixture success is not proof of an enabled production integration.

Browser authorization pages use `Referrer-Policy: strict-origin` (paths and query values are not sent); signed API responses use `no-referrer`. Chromium suppresses the form POST Origin under `no-referrer`, so that policy cannot be used on the same-origin confirmation form while also enforcing an exact Origin check. The isolated real-browser acceptance test exercises the form, rather than weakening Origin verification.

## Association lookup and local presentation cache

`POST /v1/account-links/binding` accepts the canonical empty object `{}` with the existing DMP HTTP signature. The mailbox is taken exclusively from the verified request identity. The response is `{mailboxId,linked,revision,revoked}`; absent associations have revision 0, linked false and revoked false. Revoked associations keep their positive revision and return linked false. The response is no-store and never contains the ARC identity, recovery ciphertext, proof or another mailbox's association. This query creates no intent and requires no browser approval. Membership eligibility remains independently checked at sending time.

Clients may persist association presentation metadata keyed by exact service origin and mailbox identity: schema version, origin, mailbox ID, link/revocation status, association revision and last verification time. Do not persist passwords or signing keys in this record. Restore it on login and reconcile it with the signed lookup. A network failure preserves the last record with an explicit unverified/offline label; a verified revocation replaces it. A local record never grants member benefits or download permission.

Existing-mailbox linking in the browser extension sends `capsule: null`: association does not require exporting keys, creating a recovery capsule, or downloading a file. Previously persisted completion payloads retain their exact retry semantics. The server retains the signed identity association for authorization; local association metadata is included in the existing full client backup and remains advisory after import. Connecting with the original mailbox can query the server association without new ARC consent. Legacy encrypted recovery imports and optional protocol backup APIs remain compatible; existing remote capsules are not automatically removed.

## HTTP contract

All signed JSON is exact-field canonical JCS. Except public capability discovery and browser authorization/approval, requests use DMP HTTP signatures. Responses are no-store. Disabled/unconfigured association capability returns `enabled:false` for discovery and unavailable for protected operations.

| Method/path                                   | Request                              | Result/binding                                                                                             |
| --------------------------------------------- | ------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| `GET /v1/account-links/capabilities`          | Public                               | `{version:1,enabled,authorizationOrigin}`; no private association or bridge data                           |
| `POST /v1/account-links/intents`              | `{intentId,operation,pkceChallenge}` | `{intentId,authorizationUrl,expiresAt,displayCode}`; signer fixes client identity; changed retry conflicts |
| `GET /account/authorize?id=…`                 | ARC browser session                  | Explicit same-origin approval UI with CSRF protection                                                      |
| `POST /account/approve`                       | Form `{id,csrf,consent:'yes'}`       | Freezes approved statement; never automatic consent                                                        |
| `POST /v1/account-links/intents/:id/status`   | `{verifier}`                         | Pending or approved statement; same authenticated client and PKCE                                          |
| `POST /v1/account-links/intents/:id/complete` | `{verifier,proof,capsule}`           | `{mailboxId,revision,revoked,capsule}`; only recovery returns ciphertext                                   |
| `PUT /v1/account-links/backup`                | `{expectedRevision,capsule}`         | Mailbox-signed CAS; null deletes ciphertext without erasing association history                            |
| `POST /v1/account-links/binding`              | `{}`                                 | Own-mailbox presentation state as defined above                                                            |

Link/revoke completion proves the complete approved statement; recovery uses its approved temporary client and null proof/capsule. Link capsules are optional. Completion retries keep the same intent/payload with fresh HTTP nonces; expiry or changed binding/backup revisions cannot return stale recovery ciphertext. An upstream identity no longer able to authenticate may require offline recovery. See [Native ARC implementation](https://github.com/didmail-org/server/blob/main/blocklet/providers/didmail-http/source/http/account-links.ts) and its account-link tests.
