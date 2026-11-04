# Member direct-storage extension

Status: implemented working draft, reviewed 2026-10-30. Scope: DMP/1, active Worker and three clients. Isolated regression is available; enterprise remote deployment and physical-device end-to-end acceptance remain release gates.

## Automatic selection and eligibility

The signed manifest field `automaticDelivery=true` explicitly opts an updated client into automatic selection. Older manifests without the field retain the NFT path. This is one compose flow, not a separate user-selected mode.

When both parties are eligible, actively bound, non-guest members of this node and blocking rules permit the send, the node stores end-to-end encrypted mail directly: no envelope, payment, mail NFT, VC broadcast or other chain notification. The recipient must have a valid receiving key. A selected envelope is only an external candidate; it cannot determine internal retention. An automatic request without an envelope uses `planId=auto`; if internal delivery is unavailable, a real external envelope must be selected and reviewed.

Member-capable discovery returns locally published envelope summaries as estimates without waiting for envelope or service-node NFT chain reads. Formal external quotes still verify actual on-chain terms.

Before acceptance, the server checks live membership and local binding revisions again. Source failure returns 503, not “non-member.” Blocked senders cannot bypass admission by paying. Eligibility changes after an internal quote cause a terms conflict; external payment/publication requires a new preparation and fresh client authorization. Accepted tasks never change delivery type or charge again because membership later changes.

An internal sender needs at least one **actively, unrevoked self-staked native token**. Revoked amounts awaiting withdrawal do not count. This is a read-only chain check distinct from external gas eligibility. Internal delivery does not depend on a node NFT, factory availability or node gas stake. Receiving and historical downloads do not require a new stake. Earlier account/stake transactions may still exist on-chain.

## Signed terms and receipts

Reuse DMP/1 HTTP authentication, manifest signatures, HPKE, chunk AEAD and digests. `automaticDelivery` is an explicit signed extension; existing paid manifest signatures are not rewritten.

An internal quote has `delivery=server`, `settlement.profile=none`, all monetary amounts zero, and no `funding`. `memberBindings` fixes both binding revisions and `policyRevision` fixes the node policy. Terms bind the original message, expiry and internal retention. Preparation returns `paymentRequest.mode=server` without an unsigned payment. Submission authorizes the exact `quoteId` and `delivery=server`; `signedTransaction` is forbidden. Payment metadata retained in existing discovery structures does not authorize constructing a payment.

The server-signed receipt is the offline delivery credential; no duplicate VC or chain attestation is created. It has `delivery=server` and `termsSha256`, the JCS SHA-256 digest of the complete signed quote. It binds message digests, participants, service, acceptance/delivery times and expiry. It must omit `payment`, `funding` and `index`. Clients verify service and sender signatures, identities and digests. External receipts retain strict NFT and payment/funding evidence verification.

## Durable acceptance

Upload, complete digest verification, acceptance and delivery are separate stages. Acceptance CAS binds both local associations, policy revision, original terms, all receiving keys and upload lifecycle. Remote ARC changes cannot be committed atomically with D1; the final authoritative observation is the membership decision. Local revocation and acceptance serialize through database conditions.

Only mark `delivered` once all ciphertext is durable and the receipt and mailbox entry are queryable. This does not mean read or downloaded. Keep existing leases, idempotent IDs, immutable manifests and restart recovery. The internal path does not call settlement/mint adapters or occupy chain-wallet lanes.

## Inbox and local persistence

Internal and external lists remain separate and classify mail by its accepted delivery type, not current membership. Internal pagination uses a monotonically increasing node delivery sequence, not UUID ordering. Authenticate the account from the request signature and scope cursors to service, account and mailbox. Preserve `serviceId`, `messageId` and manifest digest; conflicting digests under the same identity key must not overwrite local mail.

The Chrome extension, React Native and Flutter clients combine internal and external mail in one inbox, ordered newest first by message creation time. Delivery types and synchronization requests remain distinct. Ordinary refresh also synchronizes internal mail. Download and verify the body and all attachments into local encrypted storage. A readable body is not complete attachment persistence. Retain failed attachments for retry; one failed message must not block the batch. Verify descriptors against the manifest. React Native persists per message rather than retaining the mailbox's attachments in memory.

Backups include ciphertext, attachments, receipt, manifest and historical private encryption keys. A successful download on one device must not prematurely delete the node copy. Node retention still applies. Server migration, offboarding recovery and cross-node federation are outside this extension.

Current clients rescan and idempotently merge on refresh. The server supplies stable increasing pagination cursors, but clients do not yet persist an incremental watermark across refreshes.

## Deployment and limits

Apply [0016_member_mail.sql](https://github.com/didmail-org/server/blob/main/workers/migrations/0016_member_mail.sql) and [0017_external_upload_sessions.sql](https://github.com/didmail-org/server/blob/main/workers/migrations/0017_external_upload_sessions.sql). Existing rows default to `delivery_kind=nft`; historical ciphertext and transactions are not rewritten. The external unpaid-session index excludes internal uploads. Internal indexes use separate tables. Configure a trusted `ARC_MEMBERS` source, enabled account associations and actual user bindings. A cached client badge never grants authorization.

| Deployment setting | Default | Meaning |
| ------------------ | ------- | ------- |
| `DMP_INTERNAL_RETENTION_DAYS` | `30` | Internal node retention, allowed range 1–36500 days |

Internal mail has no daily message-count quota, cumulative storage quota per sender or node, or pending-upload task cap. This applies both to new internal tasks and external quotes refreshed into internal delivery. The former `DMP_INTERNAL_MEMBER_BYTES`, `DMP_INTERNAL_NODE_BYTES` and `DMP_INTERNAL_DAILY_MESSAGES` settings are ignored and should be removed from deployment configuration. The historical `reserved_bytes` database column remains for migration compatibility and does not enforce a quota.

The eight-session unpaid upload allowance applies only to external NFT tasks, including a quote refreshed from internal to external delivery. Internal tasks do not consume those slots. Existing attachment counts, per-file/total and whole-message size limits, transport concurrency, request rate limits, upload expiry and node retention still apply. Configuration changes do not alter accepted terms retroactively.

## Compatibility and verification

[Public vectors](fixtures/member-mail.json) and SDK fixtures cover signatures, receipts and ciphertext, including independent Dart verification. Tests must cover revocation, inactive/guest/blocked members, source timeout, changed eligibility, no-envelope sends, payment isolation, integrity, concurrent/restarted retries, sequence ordering, account isolation, complete attachments and backup restore. Never broadcast real transactions or messages from automated tests. See [implementation status](https://github.com/didmail-org/overview/blob/main/docs/status.md) for acceptance boundaries.
