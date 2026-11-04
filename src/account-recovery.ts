import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { b64u, unb64u, canonicalize, parseCanonical, utf8, concat, randomBytes, addressOf, validUnicode } from './codec';
import { seedOf, signingPublicKey, encryptionPublicKey, keyIdOf, type IdentityMatcher } from './crypto';
import { expectKeys, validateKeyRecord, validateKeyRevocation } from './message';
import type { KeyRecord, KeyRevocation } from './types';

const DOMAIN = 'DIDMAIL-ACCOUNT-RECOVERY/1\n';
export const ACCOUNT_RECOVERY_MAX_BYTES = 131072;
export interface AccountRecoveryBody {
  version: 1; mailboxId: string; seed: string;
  keys: { record: KeyRecord; privateKey: string }[];
  revocations: KeyRevocation[];
}
export interface AccountRecoveryCapsule {
  format: 'didmail-account-recovery'; version: 1; mailboxId: string;
  kdf: 'PBKDF2-SHA256'; iterations: 600000; salt: string; nonce: string; ciphertext: string;
}
/** Native clients may supply an equivalent native PBKDF2 implementation. */
export type AccountRecoveryKdf = (password: Uint8Array, salt: Uint8Array, iterations: number) => Promise<Uint8Array>;
const derive: AccountRecoveryKdf = (password, salt, iterations) => pbkdf2Async(sha256, password, salt, { c: iterations, dkLen: 32 });
function passwordBytes(password: string): Uint8Array {
  validUnicode(password);
  const bytes = utf8(password);
  if (password.length === 0 || bytes.length > 1024) throw new Error('Backup password must not be empty and must be at most 1024 UTF-8 bytes');
  return bytes;
}
/** Validates public bounds before any costly KDF or persistence. */
export function validateAccountRecoveryCapsule(value: unknown): asserts value is AccountRecoveryCapsule {
  expectKeys(value, ['format', 'version', 'mailboxId', 'kdf', 'iterations', 'salt', 'nonce', 'ciphertext']);
  if (utf8(canonicalize(value)).length > ACCOUNT_RECOVERY_MAX_BYTES || value.format !== 'didmail-account-recovery' || value.version !== 1 || value.kdf !== 'PBKDF2-SHA256' || value.iterations !== 600000) throw new Error('Invalid recovery capsule');
  addressOf(value.mailboxId as string);
  unb64u(value.salt as string, 16); unb64u(value.nonce as string, 12);
  const ciphertext = unb64u(value.ciphertext as string);
  if (ciphertext.length < 16 || ciphertext.length > 65536 + 16) throw new Error('Invalid recovery ciphertext size');
}
export function validateAccountRecoveryBody(value: unknown, expectedMailbox: string, matches: IdentityMatcher): asserts value is AccountRecoveryBody {
  expectKeys(value, ['version', 'mailboxId', 'seed', 'keys', 'revocations']);
  addressOf(expectedMailbox);
  if (value.version !== 1 || value.mailboxId !== expectedMailbox || utf8(canonicalize(value)).length > 65536 || !matches(signingPublicKey(unb64u(value.seed as string, 32)), expectedMailbox)) throw new Error('Recovery mailbox mismatch');
  if (!Array.isArray(value.keys) || value.keys.length > 64 || !Array.isArray(value.revocations) || value.revocations.length > 256) throw new Error('Recovery archive exceeds supported bounds');
  const seen = new Set<string>();
  for (const pair of value.keys) {
    expectKeys(pair, ['record', 'privateKey']);
    const record = pair.record as KeyRecord;
    validateKeyRecord(record, matches, Date.parse(record.createdAt));
    const secret = unb64u(pair.privateKey as string, 32);
    try {
      if (Date.parse(record.createdAt)>Date.now()+30000 || record.ownerId !== expectedMailbox || record.keyId !== keyIdOf(encryptionPublicKey(secret)) || seen.has(record.keyId)) throw new Error('Invalid archived key');
      seen.add(record.keyId);
    } finally { secret.fill(0); }
  }
  seen.clear();
  for (const record of value.revocations as KeyRevocation[]) {
    validateKeyRevocation(record, matches);
    if (record.ownerId !== expectedMailbox || seen.has(record.keyId)) throw new Error('Invalid archived revocation');
    seen.add(record.keyId);
  }
}
export async function encryptAccountRecovery(body: AccountRecoveryBody, password: string, matches: IdentityMatcher, kdf: AccountRecoveryKdf = derive): Promise<AccountRecoveryCapsule> {
  validateAccountRecoveryBody(body, body.mailboxId, matches);
  const salt = randomBytes(16), nonce = randomBytes(12), pass = passwordBytes(password);
  const header = { format: 'didmail-account-recovery' as const, version: 1 as const, mailboxId: body.mailboxId, kdf: 'PBKDF2-SHA256' as const, iterations: 600000 as const, salt: b64u(salt), nonce: b64u(nonce) };
  let key: Uint8Array | undefined;
  const plain = utf8(canonicalize(body));
  try {
    key = await kdf(pass, concat(utf8(DOMAIN), salt), 600000);
    if (key.length !== 32) throw new Error('Invalid derived key');
    const capsule = { ...header, ciphertext: b64u(gcm(key, nonce, utf8(DOMAIN + canonicalize(header))).encrypt(plain)) };
    validateAccountRecoveryCapsule(capsule); return capsule;
  } finally { pass.fill(0); key?.fill(0); plain.fill(0); }
}
/** Returns a fully validated archive. Caller commits the entire archive atomically. */
export async function decryptAccountRecovery(capsule: AccountRecoveryCapsule, password: string, expectedMailbox: string, matches: IdentityMatcher, kdf: AccountRecoveryKdf = derive): Promise<AccountRecoveryBody> {
  validateAccountRecoveryCapsule(capsule);
  if (capsule.mailboxId !== expectedMailbox) throw new Error('Recovery mailbox mismatch');
  const { ciphertext, ...header } = capsule, pass = passwordBytes(password);
  let key: Uint8Array | undefined, plain: Uint8Array | undefined;
  try {
    key = await kdf(pass, concat(utf8(DOMAIN), unb64u(header.salt, 16)), 600000);
    if (key.length !== 32) throw new Error('Invalid derived key');
    plain = gcm(key, unb64u(header.nonce, 12), utf8(DOMAIN + canonicalize(header))).decrypt(unb64u(ciphertext));
    const body = parseCanonical(plain);
    validateAccountRecoveryBody(body, expectedMailbox, matches); return body;
  } finally { pass.fill(0); key?.fill(0); plain?.fill(0); }
}
export function accountRecoveryBody(mailboxId: string, secret: Uint8Array, keys: AccountRecoveryBody['keys'], revocations: KeyRevocation[]): AccountRecoveryBody {
  return { version: 1, mailboxId, seed: b64u(seedOf(secret)), keys, revocations };
}
