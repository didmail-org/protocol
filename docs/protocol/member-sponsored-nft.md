# Node-sponsored member-envelope NFT

Status: implemented DMP/1 extension. Audience: protocol implementers. Same-node eligible member pairs use [direct storage](member-mail.md) when the client opts in; this document describes the external NFT outcome and older compatible NFT requests.

## Quote and authorization

Discovery advertises `node-sponsored-nft`. Public default discovery exposes only Public envelopes. Access to Members envelopes requires mailbox-signed listing requests and live, unrevoked, active non-guest membership with blocking checks.

A Members envelope with actual on-chain price zero adds `funding={mode:"node-sponsored",sponsorId:serviceId,amount:indexAmount}` to the signed quote. `envelopeAmount`, `storageAmount`, `totalAmount`, `serviceAmount` and `developerAmount` are all `"0"`. `indexAmount` is the positive NFT mint cost paid by the node. `settlement.payerId` is the actual funding `serviceId`; the manifest and HTTP signatures still identify the sender. The index cost is not added to the sender total. Paid quotes retain their original accounting equations and authorization.

After verifying all chunks and complete digests, preparation returns `paymentRequest.mode=node-sponsored` and `quoteId`. `unsignedTransaction` is an empty string: no sender payment exists, and clients must not sign or broadcast it. Explicit confirmation submits the DID-authenticated `POST /v1/messages/{id}/submit` body `{quoteId,fundingMode:"node-sponsored"}`, without `signedTransaction`. The signature covers the full URI/body, nonce prevents replay, and quote ID binds the immutable manifest digest. Unsupported clients reject the extension rather than creating a zero-amount TransferV3.

## Acceptance and settlement

Recheck preparation, upload/quote expiry, receiving-key revocation and membership before acceptance. CAS binds membership association revision, policy, original quote, manifest/chunks and upload lifecycle. Accepted retries return the original task.

The existing operator wallet lane serializes NFT preparation. Persist the complete signed transaction and hash before broadcasting; after response loss or restart, query/rebroadcast those same bytes. Verify gas eligibility for the node that actually funds the mint. Do not create a payer lane, `signed_payment` or `payment_hash` for this mode.

One node-signed AcquireAssetV3 both pays the positive mint cost and creates the recipient-owned NFT. Its locator omits `paymentTransactionId` and includes `funding={mode:"node-sponsored",quoteId}`, retaining `messageId`, `manifestSha256`, `serviceId` and endpoint. The factory's receipt input is an empty string because no sender payment hash exists.

## Receipt and reading

The signed receipt retains message, identity and retention fields plus confirmed `index` evidence; it omits `payment` and includes quote-consistent `funding`. Verify factory, recipient ownership, locator, original signed hash, confirmation model and network before delivery. Reject receipts with a fabricated sender payment, zero node cost or absent NFT confirmation.

The recipient can be outside the organization. Reading uses the real NFT locator and original node ciphertext. Later membership changes cannot replace an accepted task's signed transaction. There is no VC compatibility path.

## Evidence

SDK, Worker and all clients implement explicit branches. Isolated tests check real transaction encoding, a positive node mint, single durable broadcast intent, restart recovery, receipts and attachment decryption. They do not prove a new live-chain delivery. See [release gates](https://github.com/didmail-org/didmail/blob/main/docs/status.md).
