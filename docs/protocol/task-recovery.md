# Original-task recovery

Status: implemented client mail-recovery contract. Audience: client/server maintainers. These are client recovery rules, not new wire states.

## Automatic recovery is read-only

Query the original accepted task's status; do not sign or submit payment automatically. Keep the original quote, task, signed bytes and ciphertext. A missing message row cannot be reconstructed merely by resubmitting a signature, and a 404 does not prove that the original payment was never broadcast.

Continue querying ordinary queued/payment/index/delivery states. Map missing status to local `recovery_required`, and uploading/awaiting-signature to local `confirmation_required`. Retain them for later queries without blocking other messages. Unknown states/revisions/timestamps and 401/403/429/5xx remain distinct errors, not evidence of nonpayment.

## Foreground original submission

Only a still-valid original quote/task awaiting the exact retained signature, without contradictory local payment/delivery evidence, may offer explicit original-submission review. Validate original proofs, both signatures, exact unsigned reconstruction, configured chain fees and immutable message bindings. After approval recheck fee, service status, local record and operation scope before dispatching the same bytes.

Missing/expired/reconciliation or already paid/delivered local state blocks submission, including when transaction IDs are absent. Never requote, sign a replacement or treat server data loss as a chargeable new task. Original unbroadcast, rejected or paid-but-unminted outcomes need authoritative original-chain/operator reconciliation and a supported explicit recovery protocol.

## Scope and persistence

Use the original node, captured account, task and database lifetime, not the currently selected replacement. Late task-store persistence cannot authorize stale dispatch. Account/node/page/foreground/selected-message changes invalidate prompts/results. Recheck ownership and immutable identity inside local writes; retain original financial and ciphertext evidence through backup restore.

A service status or receipt alone is not independent chain consensus proof. Contact/namecard recovery is separately capability-gated; these DMP mail rules do not enable it. See [payment authorization](payment-authorization.md) and [server recovery scope](https://github.com/didmail-org/server/blob/main/docs/contact-recovery.md).
