import { sha256 } from '@noble/hashes/sha2.js';
import { base64, base64urlnopad, hex } from '@scure/base';
export const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);
export const text = (bytes: Uint8Array): string => new TextDecoder('utf-8', { fatal: true }).decode(bytes);
export const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
};
export const b64u = (bytes: Uint8Array): string => base64urlnopad.encode(bytes);
export const unb64u = (value: string, length?: number): Uint8Array => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('Invalid base64url');
  const bytes = base64urlnopad.decode(value);
  if (b64u(bytes) !== value || (length !== undefined && bytes.length !== length)) throw new Error('Noncanonical base64url');
  return bytes;
};
export const b64 = (bytes: Uint8Array): string => base64.encode(bytes);
export const unb64 = (value: string): Uint8Array => {
  const bytes = base64.decode(value);
  if (b64(bytes) !== value) throw new Error('Noncanonical base64');
  return bytes;
};
export const digest = (bytes: Uint8Array): string => hex.encode(sha256(bytes));
export const unhex = (value: string): Uint8Array => hex.decode(value);
export function validUnicode(value: string): void {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error('Unpaired surrogate');
    } else if (c >= 0xdc00 && c <= 0xdfff) throw new Error('Unpaired surrogate');
  }
}
export function canonicalize(value: unknown, depth = 0): string {
  if (depth > 32) throw new Error('JSON nesting limit exceeded');
  if (value === null) return 'null';
  if (typeof value === 'string') { validUnicode(value); return JSON.stringify(value); }
  if (typeof value === 'boolean') return String(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) throw new Error('Unsafe JSON number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return '[' + value.map(v => canonicalize(v, depth + 1)).join(',') + ']';
  if (typeof value === 'object' && value && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)) {
    return '{' + Object.keys(value).sort().map(key => {
      validUnicode(key);
      if (['__proto__', 'prototype', 'constructor'].includes(key)) throw new Error('Forbidden JSON member');
      return JSON.stringify(key) + ':' + canonicalize((value as Record<string, unknown>)[key], depth + 1);
    }).join(',') + '}';
  }
  throw new Error('Unsupported JSON value');
}
export function parseCanonical(bytes: Uint8Array): unknown {
  const input = text(bytes);
  const value: unknown = JSON.parse(input);
  if (canonicalize(value) !== input) throw new Error('JSON must use canonical serialization without duplicate members');
  return value;
}
export const randomBytes = (length: number): Uint8Array => {
  const value = new Uint8Array(length);
  if (!globalThis.crypto?.getRandomValues) throw new Error('Secure random source required');
  for (let offset = 0; offset < length; offset += 65536) crypto.getRandomValues(value.subarray(offset, offset + 65536));
  return value;
};
export function uuid(): string {
  const b = randomBytes(16); b[6] = (b[6] & 15) | 64; b[8] = (b[8] & 63) | 128;
  const h = hex.encode(b); return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
export const isUuid = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
export const isDigest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
export const amount = (value: unknown): bigint => {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,77})$/.test(value)) throw new Error('Invalid amount');
  return BigInt(value);
};
export const identityId = (address: string): string => address.startsWith('did:abt:') ? address : `did:abt:${address}`;
export const addressOf = (did: string): string => {
  if (!/^did:abt:z[1-9A-HJ-NP-Za-km-z]{20,64}$/.test(did)) throw new Error('Unsupported identity');
  return did.slice(8);
};
