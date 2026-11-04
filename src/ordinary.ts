import { sha3_256 } from "@noble/hashes/sha3.js";
import { base58 } from "@scure/base";
import {
  canonicalize,
  utf8,
  digest,
  addressOf,
  identityId,
  isUuid,
  isDigest,
  unb64u,
  b64u,
  amount,
} from "./codec";
import {
  signArtifact,
  unsignedArtifact,
  verifyArtifact,
  ed25519,
  type Proof,
  type IdentityMatcher,
} from "./crypto";
import {
  validateManifestVersion,
  sealEncryptedMessage,
  decryptEncryptedBlob,
  expectKeys,
  validTimestamp,
  type EncryptionManifest,
} from "./message";
import {
  validateChainConfirmation,
  confirmationPolicy,
} from "./chain-confirmation";
import type { ChainConfirmation, ConfirmationPolicy } from "./types";

export const ORDINARY_NOTIFICATION_PROFILE =
  "arcblock-transfer-v2-vc/1" as const;
export const ORDINARY_PLAN_ID = "ordinary";
export type OrdinaryManifest = EncryptionManifest & { protocolVersion: 2 };
export interface OrdinaryLimits {
  enabled: boolean;
  maxCount: number;
  maxFileBytes: number;
  maxTotalBytes: number;
  maxMessageCiphertextBytes: number;
}
export interface OrdinaryTerms {
  protocolVersion: 2;
  termsId: string;
  messageId: string;
  manifestSha256: string;
  senderId: string;
  recipientId: string;
  serviceId: string;
  planId: "ordinary";
  serviceEndpoint: string;
  policyRevision: number;
  issuedAt: string;
  expiresAt: string;
  totalAmount: string;
  retentionSeconds: number;
  limits: OrdinaryLimits;
  settlement: { profile: "none" } | OrdinaryPaidSettlement;
  notification: {
    profile: typeof ORDINARY_NOTIFICATION_PROFILE;
    chainId: string;
    chainEndpoint: string;
    confirmationPolicy: ConfirmationPolicy;
  };
  proof: Proof;
}
export interface OrdinaryPaidSettlement {
  profile: "arcblock-transfer-v3-ordinary/1";
  assetId: string;
  decimals: 18;
  payerId: string;
  payeeId: string;
  baseAmount: string;
  storageAmount: string;
  pricePerBytePerDay: string;
}
export interface OrdinaryPaymentRequest {
  encoding: "base64url";
  termsId: string;
  termsSha256: string;
  unsignedTransaction: string;
}
/** All ordinary service income goes to the origin node. No NFT or developer fee. */
export function validateOrdinarySettlement(
  terms: OrdinaryTerms,
  manifest: OrdinaryManifest,
) {
  const total = amount(terms.totalAmount),
    settlement = terms.settlement;
  if (total > 2n ** 256n - 1n) fail();
  if (settlement.profile === "none") {
    expectKeys(settlement, ["profile"]);
    if (total !== 0n) fail();
    return;
  }
  expectKeys(settlement, [
    "profile",
    "assetId",
    "decimals",
    "payerId",
    "payeeId",
    "baseAmount",
    "storageAmount",
    "pricePerBytePerDay",
  ]);
  addressOf(identityId(settlement.assetId));
  const base = amount(settlement.baseAmount),
    storage = amount(settlement.storageAmount),
    price = amount(settlement.pricePerBytePerDay);
  const bytes = manifest.blobs
    .filter((b) => b.blobId !== manifest.documentBlobId)
    .reduce((n, b) => n + BigInt(b.sizeBytes - 16 * b.chunkCount), 0n);
  if (
    settlement.profile !== "arcblock-transfer-v3-ordinary/1" ||
    total <= 0n ||
    settlement.decimals !== 18 ||
    settlement.payerId !== manifest.senderId ||
    settlement.payeeId !== manifest.serviceId ||
    base + storage !== total ||
    storage !== bytes * price * BigInt(terms.retentionSeconds / 86400) ||
    !Number.isInteger(terms.retentionSeconds / 86400)
  )
    fail();
}
export const ordinaryPaymentMetadata = (
  manifest: OrdinaryManifest,
  terms: OrdinaryTerms,
) => ({
  protocolVersion: 2,
  messageId: manifest.messageId,
  manifestSha256: ordinaryManifestHash(manifest),
  termsId: terms.termsId,
  termsSha256: ordinaryTermsHash(terms),
  serviceId: manifest.serviceId,
});
export interface OrdinaryCredential {
  "@context": "https://schema.arcblock.io/v0.1/context.jsonld";
  id: string;
  type: "DIDMailDeliveryCredential";
  issuer: { id: string; pk: string; name: string };
  issuanceDate: string;
  credentialSubject: {
    id: string;
    protocolVersion: 2;
    messageId: string;
    manifestSha256: string;
    serviceId: string;
    endpoint: string;
    termsSha256: string;
    profile: typeof ORDINARY_NOTIFICATION_PROFILE;
  };
  proof: {
    type: "Ed25519Signature";
    created: string;
    proofPurpose: "assertionMethod";
    jws: string;
  };
}
export interface OrdinaryReceipt {
  protocolVersion: 2;
  messageId: string;
  manifestSha256: string;
  termsId: string;
  termsSha256: string;
  senderId: string;
  recipientId: string;
  serviceId: string;
  acceptedAt: string;
  deliveredAt: string;
  retentionExpiresAt: string;
  payment:
    | { mode: "none" }
    | { mode: "transfer-v3"; transaction: ChainConfirmation };
  notification: {
    profile: typeof ORDINARY_NOTIFICATION_PROFILE;
    credentialSha256: string;
    transaction: ChainConfirmation;
  };
  proof: Proof;
}
const fail = (): never => {
  throw new Error("Invalid ordinary mail artifact");
};
export function ordinaryOrigin(value: string): string {
  const url = new URL(value),
    loopback =
      ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
      url.hostname.endsWith(".localhost");
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/" ||
    url.origin !== value ||
    !(url.protocol === "https:" || (url.protocol === "http:" && loopback))
  )
    return fail();
  return value;
}
function chainEndpoint(value: string) {
  const url = new URL(value);
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !(
      url.protocol === "https:" ||
      (url.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))
    )
  )
    fail();
}
export const ordinaryManifestHash = (manifest: OrdinaryManifest) =>
  digest(utf8(canonicalize(unsignedArtifact(manifest))));
export const ordinaryTermsHash = (terms: OrdinaryTerms) =>
  digest(utf8(canonicalize(terms)));
export function validateOrdinaryManifest(
  manifest: OrdinaryManifest,
  matches: IdentityMatcher,
  atTime = Date.parse(manifest.createdAt),
) {
  validateManifestVersion(manifest, 2, matches, atTime);
  if (manifest.planId !== ORDINARY_PLAN_ID) fail();
}
export function sealOrdinaryMessage(
  input: Omit<Parameters<typeof sealEncryptedMessage>[0], "planId">,
): { manifest: OrdinaryManifest; chunks: Record<string, string[]> } {
  return sealEncryptedMessage({ ...input, planId: ORDINARY_PLAN_ID }, 2) as {
    manifest: OrdinaryManifest;
    chunks: Record<string, string[]>;
  };
}
export function decryptOrdinaryBlob(
  manifest: OrdinaryManifest,
  blobId: string,
  chunks: Uint8Array[],
  owner: string,
  secret: Uint8Array,
  matches: IdentityMatcher,
  acceptedAt?: string,
  encryptionSecret?: Uint8Array,
) {
  if (manifest.planId !== ORDINARY_PLAN_ID) fail();
  return decryptEncryptedBlob(
    manifest,
    2,
    blobId,
    chunks,
    owner,
    secret,
    matches,
    acceptedAt,
    encryptionSecret,
  );
}
export function validateOrdinaryLimits(limits: OrdinaryLimits) {
  expectKeys(limits, [
    "enabled",
    "maxCount",
    "maxFileBytes",
    "maxTotalBytes",
    "maxMessageCiphertextBytes",
  ]);
  if (typeof limits.enabled !== "boolean") fail();
  for (const key of [
    "maxCount",
    "maxFileBytes",
    "maxTotalBytes",
    "maxMessageCiphertextBytes",
  ] as const)
    if (
      !Number.isSafeInteger(limits[key]) ||
      limits[key] <
        (key === "maxCount"
          ? 0
          : key === "maxMessageCiphertextBytes"
            ? 16
            : 1) ||
      limits[key] > (key === "maxCount" ? 20 : 64 * 1024 * 1024)
    )
      fail();
  if (limits.maxFileBytes > limits.maxTotalBytes) fail();
}
export function validateOrdinaryTerms(
  terms: OrdinaryTerms,
  manifest: OrdinaryManifest,
  matches: IdentityMatcher,
  now = Date.now(),
  allowExpired = false,
) {
  expectKeys(terms, [
    "protocolVersion",
    "termsId",
    "messageId",
    "manifestSha256",
    "senderId",
    "recipientId",
    "serviceId",
    "planId",
    "serviceEndpoint",
    "policyRevision",
    "issuedAt",
    "expiresAt",
    "totalAmount",
    "retentionSeconds",
    "limits",
    "settlement",
    "notification",
    "proof",
  ]);
  if (
    terms.protocolVersion !== 2 ||
    !isUuid(terms.termsId) ||
    terms.messageId !== manifest.messageId ||
    terms.manifestSha256 !== ordinaryManifestHash(manifest) ||
    terms.senderId !== manifest.senderId ||
    terms.recipientId !== manifest.recipientId ||
    terms.serviceId !== manifest.serviceId ||
    terms.planId !== ORDINARY_PLAN_ID ||
    !Number.isSafeInteger(terms.policyRevision) ||
    terms.policyRevision < 1 ||
    !Number.isSafeInteger(terms.retentionSeconds) ||
    terms.retentionSeconds < 86400 ||
    terms.retentionSeconds > 36500 * 86400 ||
    !validTimestamp(terms.issuedAt) ||
    !validTimestamp(terms.expiresAt) ||
    Date.parse(terms.issuedAt) > now + 30000 ||
    Date.parse(terms.expiresAt) <= Date.parse(terms.issuedAt) ||
    (!allowExpired && Date.parse(terms.expiresAt) <= now) ||
    !verifyArtifact("DMP2-TERMS", terms, terms.serviceId, matches)
  )
    fail();
  ordinaryOrigin(terms.serviceEndpoint);
  validateOrdinarySettlement(terms, manifest);
  expectKeys(terms.notification, [
    "profile",
    "chainId",
    "chainEndpoint",
    "confirmationPolicy",
  ]);
  if (
    terms.notification.profile !== ORDINARY_NOTIFICATION_PROFILE ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(terms.notification.chainId)
  )
    fail();
  chainEndpoint(terms.notification.chainEndpoint);
  confirmationPolicy(terms.notification.confirmationPolicy);
  validateOrdinaryLimits(terms.limits);
}
/** ArcBlock v0.1: multibase-base58 keys, Ed25519(SHA3-256(JCS(unsigned VC))). */
export function validateOrdinaryLocator(
  vc: OrdinaryCredential,
  recipientId: string,
  serviceId: string,
  matches: IdentityMatcher,
) {
  expectKeys(vc, [
    "@context",
    "id",
    "type",
    "issuer",
    "issuanceDate",
    "credentialSubject",
    "proof",
  ]);
  expectKeys(vc.issuer, ["id", "pk", "name"]);
  expectKeys(vc.proof, ["type", "created", "proofPurpose", "jws"]);
  expectKeys(vc.credentialSubject, [
    "id",
    "protocolVersion",
    "messageId",
    "manifestSha256",
    "serviceId",
    "endpoint",
    "termsSha256",
    "profile",
  ]);
  const subject = vc.credentialSubject;
  ordinaryOrigin(subject.endpoint);
  if (
    vc["@context"] !== "https://schema.arcblock.io/v0.1/context.jsonld" ||
    vc.type !== "DIDMailDeliveryCredential" ||
    typeof vc.id !== "string" ||
    !/^z[1-9A-HJ-NP-Za-km-z]{20,64}$/.test(vc.id) ||
    vc.issuer.id !== addressOf(serviceId) ||
    typeof vc.issuer.name !== "string" ||
    vc.issuer.name.length > 128 ||
    !validTimestamp(vc.issuanceDate) ||
    vc.proof.created !== vc.issuanceDate ||
    vc.proof.type !== "Ed25519Signature" ||
    vc.proof.proofPurpose !== "assertionMethod" ||
    subject.id !== addressOf(recipientId) ||
    subject.protocolVersion !== 2 ||
    !isUuid(subject.messageId) ||
    !isDigest(subject.manifestSha256) ||
    subject.serviceId !== serviceId ||
    !isDigest(subject.termsSha256) ||
    subject.profile !== ORDINARY_NOTIFICATION_PROFILE
  )
    fail();
  if (typeof vc.issuer.pk !== "string" || vc.issuer.pk.length > 64) fail();
  const pk = base58.decode(vc.issuer.pk.slice(1));
  if (
    pk.length !== 32 ||
    "z" + base58.encode(pk) !== vc.issuer.pk ||
    !matches(pk, identityId(vc.issuer.id))
  )
    fail();
  const { proof, ...unsigned } = vc;
  if (
    !ed25519.verify(
      unb64u(proof.jws, 64),
      sha3_256(utf8(canonicalize(unsigned))),
      pk,
      { zip215: false },
    )
  )
    fail();
}
/** Lossless wire packing of the signed ArcBlock VC. Repeated identities and
 * fixed profile fields come from the authenticated outer transaction. */
export function packOrdinaryCredential(vc: OrdinaryCredential): {
  dmp2vc: unknown[];
} {
  if (
    vc.issuer.name !== vc.issuer.id ||
    vc.proof.created !== vc.issuanceDate ||
    !isUuid(vc.credentialSubject.messageId) ||
    utf8(vc.credentialSubject.endpoint).length > 64
  )
    fail();
  const id = vc.credentialSubject.messageId.replace(/-/g, "");
  return {
    dmp2vc: [
      1,
      vc.id,
      b64u(Uint8Array.from(id.match(/../g)!.map((x) => parseInt(x, 16)))),
      b64u(
        Uint8Array.from(
          vc.credentialSubject.manifestSha256
            .match(/../g)!
            .map((x) => parseInt(x, 16)),
        ),
      ),
      b64u(
        Uint8Array.from(
          vc.credentialSubject.termsSha256
            .match(/../g)!
            .map((x) => parseInt(x, 16)),
        ),
      ),
      vc.credentialSubject.endpoint,
      Date.parse(vc.issuanceDate),
      vc.proof.jws,
    ],
  };
}
export function unpackOrdinaryCredential(
  value: unknown,
  context: {
    sender: string;
    recipient: string;
    publicKey: Uint8Array;
    matches: IdentityMatcher;
  },
): OrdinaryCredential {
  expectKeys(value, ["dmp2vc"]);
  const tuple = (value as { dmp2vc: unknown[] }).dmp2vc;
  if (
    !Array.isArray(tuple) ||
    tuple.length !== 8 ||
    tuple[0] !== 1 ||
    tuple.some((v, i) => i !== 0 && i !== 6 && typeof v !== "string") ||
    !Number.isSafeInteger(tuple[6]) ||
    (tuple[6] as number) < 0 ||
    context.publicKey.length !== 32
  )
    fail();
  const [_, id, message, manifest, terms, endpoint, issued, jws] = tuple as [
    number,
    string,
    string,
    string,
    string,
    string,
    number,
    string,
  ];
  const hex = (v: Uint8Array) =>
    Array.from(v, (x) => x.toString(16).padStart(2, "0")).join("");
  const h = hex(unb64u(message, 16)),
    messageId = `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  const date = new Date(issued).toISOString(),
    sender = addressOf(identityId(context.sender)),
    recipient = addressOf(identityId(context.recipient));
  const vc: OrdinaryCredential = {
    "@context": "https://schema.arcblock.io/v0.1/context.jsonld",
    id,
    type: "DIDMailDeliveryCredential",
    issuer: {
      id: sender,
      name: sender,
      pk: "z" + base58.encode(context.publicKey),
    },
    issuanceDate: date,
    credentialSubject: {
      id: recipient,
      protocolVersion: 2,
      messageId,
      manifestSha256: hex(unb64u(manifest, 32)),
      termsSha256: hex(unb64u(terms, 32)),
      endpoint,
      serviceId: identityId(sender),
      profile: ORDINARY_NOTIFICATION_PROFILE,
    },
    proof: {
      type: "Ed25519Signature",
      created: date,
      proofPurpose: "assertionMethod",
      jws,
    },
  };
  validateOrdinaryLocator(
    vc,
    identityId(recipient),
    identityId(sender),
    context.matches,
  );
  if (canonicalize(packOrdinaryCredential(vc)) !== canonicalize(value)) fail();
  return vc;
}
export function validateOrdinaryCredential(
  vc: OrdinaryCredential,
  manifest: OrdinaryManifest,
  terms: OrdinaryTerms,
  endpoint: string,
  matches: IdentityMatcher,
) {
  validateOrdinaryLocator(
    vc,
    manifest.recipientId,
    manifest.serviceId,
    matches,
  );
  ordinaryOrigin(endpoint);
  const subject = vc.credentialSubject;
  if (
    subject.messageId !== manifest.messageId ||
    subject.manifestSha256 !== ordinaryManifestHash(manifest) ||
    subject.endpoint !== endpoint ||
    endpoint !== terms.serviceEndpoint ||
    subject.termsSha256 !== ordinaryTermsHash(terms)
  )
    fail();
}
export function validateOrdinaryReceipt(
  receipt: OrdinaryReceipt,
  manifest: OrdinaryManifest,
  terms: OrdinaryTerms,
  credential: OrdinaryCredential,
  matches: IdentityMatcher,
) {
  expectKeys(receipt, [
    "protocolVersion",
    "messageId",
    "manifestSha256",
    "termsId",
    "termsSha256",
    "senderId",
    "recipientId",
    "serviceId",
    "acceptedAt",
    "deliveredAt",
    "retentionExpiresAt",
    "payment",
    "notification",
    "proof",
  ]);
  if (
    receipt.protocolVersion !== 2 ||
    receipt.messageId !== manifest.messageId ||
    receipt.manifestSha256 !== ordinaryManifestHash(manifest) ||
    receipt.termsId !== terms.termsId ||
    receipt.termsSha256 !== ordinaryTermsHash(terms) ||
    receipt.senderId !== manifest.senderId ||
    receipt.recipientId !== manifest.recipientId ||
    receipt.serviceId !== manifest.serviceId ||
    !validTimestamp(receipt.acceptedAt) ||
    !validTimestamp(receipt.deliveredAt) ||
    !validTimestamp(receipt.retentionExpiresAt) ||
    Date.parse(receipt.acceptedAt) < Date.parse(terms.issuedAt) ||
    Date.parse(receipt.acceptedAt) >= Date.parse(terms.expiresAt) ||
    Date.parse(receipt.deliveredAt) < Date.parse(receipt.acceptedAt) ||
    Date.parse(receipt.retentionExpiresAt) !==
      Date.parse(receipt.deliveredAt) + terms.retentionSeconds * 1000 ||
    !verifyArtifact("DMP2-RECEIPT", receipt, manifest.serviceId, matches)
  )
    fail();
  if (terms.settlement.profile === "none") {
    expectKeys(receipt.payment, ["mode"]);
    if (receipt.payment.mode !== "none") fail();
  } else {
    expectKeys(receipt.payment, ["mode", "transaction"]);
    if (receipt.payment.mode !== "transfer-v3") return fail();
    const evidence = receipt.payment.transaction;
    if (
      evidence.chainId !== terms.notification.chainId ||
      validateChainConfirmation(evidence) !==
        terms.notification.confirmationPolicy ||
      Date.parse(evidence.confirmedAt) > Date.parse(receipt.deliveredAt)
    )
      fail();
  }
  expectKeys(receipt.notification, [
    "profile",
    "credentialSha256",
    "transaction",
  ]);
  if (
    receipt.notification.profile !== ORDINARY_NOTIFICATION_PROFILE ||
    receipt.notification.credentialSha256 !==
      digest(utf8(canonicalize(credential))) ||
    !isDigest(receipt.notification.credentialSha256) ||
    receipt.notification.transaction.chainId !== terms.notification.chainId ||
    validateChainConfirmation(receipt.notification.transaction) !==
      terms.notification.confirmationPolicy ||
    Date.parse(receipt.notification.transaction.confirmedAt) >
      Date.parse(receipt.deliveredAt)
  )
    fail();
  validateOrdinaryCredential(
    credential,
    manifest,
    terms,
    credential.credentialSubject.endpoint,
    matches,
  );
  if (Date.parse(credential.issuanceDate) > Date.parse(receipt.deliveredAt))
    fail();
  validateOrdinaryTerms(
    terms,
    manifest,
    matches,
    Date.parse(receipt.acceptedAt),
  );
  validateOrdinaryManifest(manifest, matches, Date.parse(receipt.acceptedAt));
}
export function signOrdinaryTerms(
  value: Omit<OrdinaryTerms, "proof">,
  secret: Uint8Array,
): OrdinaryTerms {
  return signArtifact("DMP2-TERMS", value, value.serviceId, secret);
}
