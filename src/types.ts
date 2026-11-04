import type { Proof } from './crypto';
export interface KeyRecord {
  protocolVersion: 1; ownerId: string; keyId: string; cryptoSuite: string; publicKey: string;
  createdAt: string; expiresAt: string; proof: Proof;
}
export interface KeyRevocation { protocolVersion: 1; ownerId: string; keyId: string; revokedAt: string; reason: 'rotated'|'compromised'|'retired'; proof: Proof }
export interface KeyEnvelope { ownerId: string; keyId: string; keyRecord: KeyRecord; encapsulatedKey: string; ciphertext: string }
export interface BlobDescriptor { blobId: string; sizeBytes: number; chunkCount: number; ciphertextSha256: string; chunkSha256: string[] }
export interface Manifest {
  protocolVersion: 1; messageId: string; senderId: string; recipientId: string; serviceId: string;
  automaticDelivery?: true; createdAt: string; planId: string; cryptoSuite: string; keyEnvelopes: KeyEnvelope[];
  documentBlobId: string; blobs: BlobDescriptor[]; proof: Proof;
}
export type MessageState = 'uploading'|'awaiting_signature'|'queued'|'payment_pending'|'payment_confirmed'|'index_pending'|'delivered'|'reconciliation_required'|'expired'|'rejected';
export type ConfirmationPolicy = 'arcblock-committed'|'arcblock-dolt-ledger/1';
export type ChainConfirmation = {chainId:string;transactionId:string;confirmedAt:string} & (
  {blockHeight:string;confirmationPolicy?:'arcblock-committed'} |
  {confirmationPolicy:'arcblock-dolt-ledger/1';ledgerBackend:'@ocap/statedb-dolt v1.20.2'}
);
export interface Settlement {
  profile: 'arcblock-transfer-v3-mail-nft/1'|'none'; chainId: string; chainEndpoint: string;
  paymentAssetId: string; paymentAssetDecimals: 18; envelopeFactoryId: string; messageFactoryId: string;
  payerId: string; servicePayeeAddress: string; developerPayeeAddress: string; indexLocatorField: 'subject'; confirmationPolicy: ConfirmationPolicy;
}
export interface NodeFunding { mode:'node-sponsored'; sponsorId:string; amount:string }
export interface Quote {
  delivery?: 'server'; policyRevision?: number; memberBindings?: {senderRevision:number;recipientRevision:number};
  funding?: NodeFunding;
  quoteId: string; quoteVersion: number; messageId: string; manifestSha256: string; serviceId: string; planId: string;
  issuedAt: string; expiresAt: string; paymentAsset: { chainId: string; assetId: string; decimals: number; symbol: string };
  envelopeAmount: string; storageAmount: string; totalAmount: string; indexAmount: string; developerAmount: string; serviceAmount: string;
  retention: { mode: 'finite'; durationSeconds: number } | { mode: 'indefinite' };
  settlement: Settlement; proof: Proof;
}
export interface PaymentRequest { mode?: 'node-sponsored'|'server'; encoding: 'base64url'; unsignedTransaction: string; quoteId: string }
export interface DeliveryStatus { messageId: string; state: MessageState; revision: number; updatedAt: string; acceptedAt?: string; payment?: { transactionId: string }; delivery?: { transactionId: string; assetId?: string }; receipt?: Receipt; problem?: Problem; retryAfterSeconds?: number }
export interface Receipt { protocolVersion: 1; messageId: string; manifestSha256: string; quoteId: string; senderId: string; recipientId: string; serviceId: string; acceptedAt: string; deliveredAt: string; retentionExpiresAt: string|null; payment?: ChainConfirmation; funding?: NodeFunding; delivery?: 'server'; termsSha256?: string; index?: ChainConfirmation & {assetId:string}; proof: Proof }
export interface Problem { type: string; title: string; status: number; code: string; detail: string; requestId: string; recoveryAction: string; retryAfterSeconds?: number }
export interface Discovery { protocolVersions: number[]; serviceId: string; apiBaseUrl: string; signingKey: {keyId:string;publicKey:string;serviceId:string}; paymentProfile: Omit<Settlement,'payerId'>; defaultPlan: { planId:string; name:string; envelopeAmount:string; retention:Quote['retention']; imageUrl?:string }|null; limits:{maxMessageBytes:number;maxBlobCount:number;plaintextChunkBytes:number;maxDocumentBytes:number;maxConcurrentUploads:number}; features:string[] }
export interface EmailDocument { contentType: 'email'; subject: string; body: {mediaType:'text/plain'|'text/html';text:string}; attachments:{blobId:string;fileName:string;mediaType:string;sizeBytes:number}[]; inReplyTo?:string; references?:string[] }
export interface SealedMessage { manifest: Manifest; chunks: Record<string,string[]> }
