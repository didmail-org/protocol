# Client payment authorization

Status: implemented security contract for DMP/1 NFT payment clients. Audience: client/security maintainers. Internal and sponsored no-sender-payment branches use their own explicit contracts and must not invent a zero payment.

## Independent economics

Verify service discovery, pin the node identity and validate the signed quote before payment review. A valid service signature alone cannot authorize arbitrary wallet spending. Independently verify configured network/token/decimals, factory/developer/service payees, exact canonical integer amounts and conservation, expiry and fresh chain fee policy.

The prepared TransferV3 must match the quote: exact payer/public key, allowed signer headers, input/output counts/owners/token/amounts and message/manifest/quote/service binding. Reject asset transfers, extra tokens/payees, delegated/unknown authority, substituted metadata, noncanonical encodings and unsupported fields. Preserve the accepted protobuf or CBOR wire format; a local decode/encode roundtrip must reproduce the unsigned bytes exactly.

## Explicit consent and lifetime

Show recipient/node, envelope/storage/chain costs, full fee-inclusive total, payees/amounts, retention and expiry. Use integer base units throughout. Approval is page-owned and specific to that reviewed result. Recheck policy/key/fee and captured account/node/database/draft/foreground lifetime after approval and before each signing/dispatch boundary. Switching away and back cannot reactivate an old consent.

SDK callers expose guarded signing callbacks and public identity, not unrestricted raw-secret wallet objects. Cancellation before approval causes no signing; cancellation after dispatched work cannot promise remote rollback. Keep progress and uncertain outcomes explicit.

## Durable evidence

Construct both signatures in the required order and independently verify them. Before network submission, durably preserve complete original signed/unsigned bytes, accepted quote, immutable message identity and required encrypted task content. Response loss is not nonpayment. Do not replace a transaction, nonce, quote or ciphertext during recovery without a separately specified authorized workflow.

Original-byte verification and signed service receipts are separate from chain confirmation. Explicit block/Dolt policies cannot be mixed or inferred from query success. See [task recovery](task-recovery.md), [DMP/1](dmp-1/specification.md) and [current release gates](https://github.com/didmail-org/didmail/blob/main/docs/status.md).

## Compatibility evidence

The native clients use matching public payment-authorization vectors, including independently generated protobuf/CBOR bytes and re-encoded malicious mutations. A synthetic already-accepted quote with an empty proof tests economic guards, not cryptographic proof verification. Runtime tests must additionally cover real quote proofs, native encoders/signers, durable journals, stale scope and no egress on rejection. Fixtures never broadcast real chain transactions.
