import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { extract, expand, hkdf } from '@noble/hashes/hkdf.js';
import { gcm } from '@noble/ciphers/aes.js';
import { b64u, unb64u, concat, utf8, canonicalize, randomBytes, digest } from './codec';
export const CRYPTO_SUITE = 'HPKE-X25519-HKDF-SHA256-AES256GCM' as const;
export type IdentityMatcher = (publicKey: Uint8Array, identityId: string) => boolean;
export interface Proof { algorithm: 'Ed25519'; verificationMethod: string; publicKey: string; signature: string }
export const seedOf = (secret: Uint8Array): Uint8Array => {
  if (secret.length !== 32 && secret.length !== 64) throw new Error('Ed25519 seed or secret key required');
  return secret.slice(0, 32);
};
export const signingPublicKey = (secret: Uint8Array): Uint8Array => ed25519.getPublicKey(seedOf(secret));
export function signArtifact<T extends object>(domain: string, value: T, signerId: string, secret: Uint8Array): T & { proof: Proof } {
  if ('proof' in value) throw new Error('Artifact already signed');
  const input = concat(utf8(domain + '\n'), utf8(canonicalize(value)));
  return { ...value, proof: { algorithm: 'Ed25519', verificationMethod: signerId + '#identity', publicKey: b64u(signingPublicKey(secret)), signature: b64u(ed25519.sign(input, seedOf(secret))) } };
}
export function unsignedArtifact<T extends { proof: Proof }>(artifact: T): Omit<T, 'proof'> { const { proof: _, ...unsigned } = artifact; return unsigned; }
export function verifyArtifact(domain: string, artifact: { proof: Proof }, signerId: string, matches: IdentityMatcher): boolean {
  try {
    const proof = artifact.proof;
    if (!proof || proof.algorithm !== 'Ed25519' || proof.verificationMethod !== signerId + '#identity' || Object.keys(proof).sort().join(',') !== 'algorithm,publicKey,signature,verificationMethod') return false;
    const pk = unb64u(proof.publicKey, 32);
    return matches(pk, signerId) && ed25519.verify(unb64u(proof.signature, 64), concat(utf8(domain + '\n'), utf8(canonicalize(unsignedArtifact(artifact)))), pk, { zip215: false });
  } catch { return false; }
}
const empty = new Uint8Array();
const i2osp = (n: number, size: number): Uint8Array => { const result = new Uint8Array(size); for (let i=size-1;i>=0;i--) { result[i] = n & 255; n = Math.floor(n/256); } if (n) throw new Error('Integer overflow'); return result; };
const kemSuite = concat(utf8('KEM'), i2osp(32, 2));
const hpkeSuite = concat(utf8('HPKE'), i2osp(32, 2), i2osp(1, 2), i2osp(2, 2));
const lextract = (suite: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array) => extract(sha256, concat(utf8('HPKE-v1'), suite, utf8(label), ikm), salt);
const lexpand = (suite: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, length: number) => expand(sha256, prk, concat(i2osp(length, 2), utf8('HPKE-v1'), suite, utf8(label), info), length);
function hpkeContext(dh: Uint8Array, enc: Uint8Array, recipient: Uint8Array, info: Uint8Array) {
  if (dh.every(b => b === 0)) throw new Error('Invalid X25519 shared secret');
  const shared = lexpand(kemSuite, lextract(kemSuite, empty, 'eae_prk', dh), 'shared_secret', concat(enc, recipient), 32);
  const context = concat(new Uint8Array([0]), lextract(hpkeSuite, empty, 'psk_id_hash', empty), lextract(hpkeSuite, empty, 'info_hash', info));
  const secret = lextract(hpkeSuite, shared, 'secret', empty);
  return { key: lexpand(hpkeSuite, secret, 'key', context, 32), nonce: lexpand(hpkeSuite, secret, 'base_nonce', context, 12) };
}
export function hpkeSeal(recipient: Uint8Array, info: Uint8Array, plaintext: Uint8Array): { encapsulatedKey: string; ciphertext: string } {
  return hpkeSealWithEphemeral(recipient, info, plaintext, randomBytes(32));
}
// Low-level vector hook; applications call hpkeSeal, never supply deterministic randomness.
export function hpkeSealWithEphemeral(recipient: Uint8Array, info: Uint8Array, plaintext: Uint8Array, ephemeralSecret: Uint8Array, aad = empty, sequence = 0) {
  const enc = x25519.getPublicKey(ephemeralSecret);
  const context = hpkeContext(x25519.getSharedSecret(ephemeralSecret, recipient), enc, recipient, info);
  const sequenceBytes = i2osp(sequence, 12);
  const nonce = context.nonce.map((v, i) => v ^ sequenceBytes[i]);
  return { encapsulatedKey: b64u(enc), ciphertext: b64u(gcm(context.key, nonce, aad).encrypt(plaintext)) };
}
export function hpkeOpen(secret: Uint8Array, enc: Uint8Array, info: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const pk = x25519.getPublicKey(secret);
  const context = hpkeContext(x25519.getSharedSecret(secret, enc), enc, pk, info);
  return gcm(context.key, context.nonce, empty).decrypt(ciphertext);
}
export const recoveryEncryptionSecret = (secret: Uint8Array): Uint8Array => hkdf(sha256, seedOf(secret), utf8('DMP1 wallet encryption key'), utf8('X25519 recovery key'), 32);
export const encryptionPublicKey = (secret: Uint8Array): Uint8Array => x25519.getPublicKey(secret);
export const keyIdOf = (publicKey: Uint8Array): string => digest(publicKey);
export const blobKey = (contentKey: Uint8Array, messageId: string, blobId: string): Uint8Array => hkdf(sha256, contentKey, utf8(messageId), utf8('DMP1-BLOB\n' + blobId), 32);
const chunkNonce = (index: number): Uint8Array => { if (!Number.isSafeInteger(index) || index < 0) throw new Error('Invalid chunk index'); return i2osp(index, 12); };
const chunkAad = (messageId: string, blobId: string, index: number, count: number) => utf8(`DMP1-CHUNK\n${messageId}\n${blobId}\n${index}\n${count}`);
export const encryptChunk = (key: Uint8Array, messageId: string, blobId: string, index: number, count: number, bytes: Uint8Array): Uint8Array => gcm(key, chunkNonce(index), chunkAad(messageId, blobId, index, count)).encrypt(bytes);
export const decryptChunk = (key: Uint8Array, messageId: string, blobId: string, index: number, count: number, bytes: Uint8Array): Uint8Array => gcm(key, chunkNonce(index), chunkAad(messageId, blobId, index, count)).decrypt(bytes);
export { ed25519, sha256 };

// Local journal protection is separate from wire encryption. Never transmit this key.
export function encryptLocalRecord(secret:Uint8Array,ownerId:string,purpose:string,plain:Uint8Array):string {
  const key=hkdf(sha256,seedOf(secret),utf8('DMP1 local journal'),utf8(ownerId),32),nonce=randomBytes(12);
  try{return b64u(concat(nonce,gcm(key,nonce,utf8(purpose)).encrypt(plain)));}finally{key.fill(0);}
}
export function decryptLocalRecord(secret:Uint8Array,ownerId:string,purpose:string,encoded:string):Uint8Array {
  const bytes=unb64u(encoded);if(bytes.length<28)throw new Error('Invalid local record');
  const key=hkdf(sha256,seedOf(secret),utf8('DMP1 local journal'),utf8(ownerId),32);
  try{return gcm(key,bytes.subarray(0,12),utf8(purpose)).decrypt(bytes.subarray(12));}finally{key.fill(0);}
}
