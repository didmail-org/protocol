# Envelope and namecard categories

Status: implemented local policy contract. Audience: server and client implementers. Categories do not change DMP/1 ciphertext, existing paid signatures or chain encodings.

## Creation, publication and selection

`envelopes.category` and `namecards.category` are `public` or `members`. Existing uncategorized records default to `public`; the former member-envelope reference migrates to `members`. Assign the category only at creation. Publication changes cannot change it: return 409 `ENVELOPE_CATEGORY_IMMUTABLE` or `NAMECARD_CATEGORY_IMMUTABLE`. Unpublishing/cleaning publication settings keeps the category and local record. Unregistered historical chain templates may be published only as Public.

Reuse the existing template creation, price, retention and publish UI. Do not add a second member default-envelope, budget or rate-policy form. Among visible published envelopes, members prefer Members, other senders see Public only, and the earliest local record in each category is the default. Clients may choose another visible envelope. Internal mail bypasses envelope terms altogether.

## Authenticated visibility

`GET /api/envelopes?page=N&pageSize=N` accepts DMP HTTP signatures covering the complete query URI and using replay-protected nonces. Resolve the authenticated mailbox through local `account_links` and current ARC membership. Eligible active non-guest users with unrevoked associations and no block see both categories. `member` and `identityId` in the response are display fields, not credentials. Responses are `private, no-store`.

Legacy `X-DIDMail-did` / `X-DIDMail-pk` headers can request the Public compatibility list; they cannot prove membership. Invalid DMP signatures must not fall back to those headers. Public discovery/default plans contain only Public templates. Membership-source failure must not grant access, preserve another account's private list or be interpreted as a paid fallback. Scope client caches to the current account and node.

Recheck category and membership during quote, upload, preparation and submission. Acceptance conditions bind the verified category and current association revision/revocation. Historical recipient download authorization does not depend on current template membership. Category is node access policy, not on-chain metadata privacy.

## Sponsored external mail

Category and price are independent. Zero is not a zero-amount payment. A zero-priced Members envelope automatically uses [node-sponsored NFT](member-sponsored-nft.md), with no separate sponsorship switch. Paid envelope rules remain unchanged. A recipient need not be a member.

## Namecards

`GET /api/namecards` uses the same signature, membership, pagination and no-store rules. Its response has `namecards`, `member` and `identityId`, without a default envelope.

Members-only use of `/api/contact/send` and `/api/contact/send/sign` requires mailbox DMP HTTP signatures over the actual JSON body. Keep existing contact identity headers for compatibility, but the signed identity must match them. Recheck category, publication, association and membership before preparation/submission, and match the saved sender when submitting. Self-reported DID/public keys cannot bypass membership. Namecard category alone does not make exchange free or node-sponsored; original namecard payment/NFT rules remain in force.
