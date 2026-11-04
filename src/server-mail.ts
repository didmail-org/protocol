import { amount, canonicalize, digest, isDigest, isUuid, utf8 } from "./codec";
import { verifyArtifact, type IdentityMatcher } from "./crypto";
import { manifestHash, validTimestamp } from "./message";
import type { Manifest, Quote, Receipt } from "./types";

export const termsHash = (quote: Quote): string =>
  digest(utf8(canonicalize(quote)));

export function validateServerQuote(
  quote: Quote,
  manifest: Manifest,
  matches: IdentityMatcher,
  atTime = Date.now(),
): void {
  const keys = [
    "quoteId",
    "quoteVersion",
    "messageId",
    "manifestSha256",
    "serviceId",
    "planId",
    "issuedAt",
    "expiresAt",
    "delivery",
    "policyRevision",
    "memberBindings",
    "paymentAsset",
    "envelopeAmount",
    "storageAmount",
    "totalAmount",
    "indexAmount",
    "developerAmount",
    "serviceAmount",
    "retention",
    "settlement",
    "proof",
  ];
  if (
    Object.keys(quote).length !== keys.length ||
    Object.keys(quote).some((k) => !keys.includes(k)) ||
    !isUuid(quote.quoteId) ||
    !Number.isSafeInteger(quote.quoteVersion) ||
    quote.quoteVersion < 1 ||
    Object.keys(quote.memberBindings || {})
      .sort()
      .join(",") !== "recipientRevision,senderRevision" ||
    Object.keys(quote.retention || {})
      .sort()
      .join(",") !== "durationSeconds,mode" ||
    manifest.automaticDelivery !== true ||
    quote.delivery !== "server" ||
    quote.settlement.profile !== "none" ||
    quote.funding !== undefined ||
    !verifyArtifact("DMP1-QUOTE", quote, manifest.serviceId, matches) ||
    quote.serviceId !== manifest.serviceId ||
    quote.messageId !== manifest.messageId ||
    quote.manifestSha256 !== manifestHash(manifest) ||
    quote.planId !== manifest.planId ||
    quote.settlement.payerId !== manifest.senderId ||
    !validTimestamp(quote.issuedAt) ||
    !validTimestamp(quote.expiresAt) ||
    Date.parse(quote.expiresAt) <= atTime ||
    Date.parse(quote.expiresAt) <= Date.parse(quote.issuedAt) ||
    !Number.isSafeInteger(quote.memberBindings?.senderRevision) ||
    (quote.memberBindings?.senderRevision || 0) < 1 ||
    !Number.isSafeInteger(quote.memberBindings?.recipientRevision) ||
    (quote.memberBindings?.recipientRevision || 0) < 1 ||
    !Number.isSafeInteger(quote.policyRevision) ||
    quote.policyRevision! < 1 ||
    quote.retention.mode !== "finite" ||
    !Number.isSafeInteger(quote.retention.durationSeconds) ||
    quote.retention.durationSeconds < 1 ||
    quote.retention.durationSeconds > 36500 * 86400 ||
    [
      "envelopeAmount",
      "storageAmount",
      "totalAmount",
      "indexAmount",
      "developerAmount",
      "serviceAmount",
    ].some((k) => amount(quote[k as "totalAmount"]) !== 0n)
  )
    throw new Error("Invalid server delivery terms");
}

/** A signed offline service attestation, never a chain confirmation. */
export function validateServerReceipt(
  receipt: Receipt,
  manifest: Manifest,
  matches: IdentityMatcher,
): void {
  const keys = [
    "protocolVersion",
    "messageId",
    "manifestSha256",
    "quoteId",
    "senderId",
    "recipientId",
    "serviceId",
    "acceptedAt",
    "deliveredAt",
    "retentionExpiresAt",
    "delivery",
    "termsSha256",
    "proof",
  ];
  if (
    Object.keys(receipt).length !== keys.length ||
    Object.keys(receipt).some((k) => !keys.includes(k)) ||
    !isUuid(receipt.quoteId) ||
    manifest.automaticDelivery !== true ||
    receipt.delivery !== "server" ||
    receipt.protocolVersion !== 1 ||
    receipt.index !== undefined ||
    receipt.payment !== undefined ||
    receipt.funding !== undefined ||
    !isDigest(receipt.termsSha256) ||
    receipt.messageId !== manifest.messageId ||
    receipt.manifestSha256 !== manifestHash(manifest) ||
    receipt.senderId !== manifest.senderId ||
    receipt.recipientId !== manifest.recipientId ||
    receipt.serviceId !== manifest.serviceId ||
    !verifyArtifact("DMP1-RECEIPT", receipt, manifest.serviceId, matches) ||
    !validTimestamp(receipt.acceptedAt) ||
    !validTimestamp(receipt.deliveredAt) ||
    !validTimestamp(receipt.retentionExpiresAt) ||
    Date.parse(receipt.deliveredAt) < Date.parse(receipt.acceptedAt) ||
    Date.parse(receipt.retentionExpiresAt) <= Date.parse(receipt.deliveredAt)
  )
    throw new Error("Invalid offline delivery credential");
}
