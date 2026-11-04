#!/usr/bin/env node
/**
 * Regenerate docs/protocol/fixtures/legacy-attachments/attachment-crypto-vectors.json
 *
 * Run from the protocol repository root after installing dependencies in the
 * sibling extension/ checkout:
 *
 *   node docs/protocol/fixtures/legacy-attachments/generate-attachment-vectors.mjs
 *
 * Uses FIXED test keys (not fromRandom) so output stays stable across regenerations.
 * Nonces are fixed (byte fill 1..5) for deterministic ciphertext; production Box.encrypt
 * uses nacl.randomBytes.
 */

import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const extensionRoot = path.resolve(__dirname, '../../../../../extension');
const require = createRequire(path.join(extensionRoot, 'package.json'));

const ocapUtil = require('@ocap/util');
const { getHasher, types } = require('@ocap/mcrypto');
const nacl = require('tweetnacl');
const ed2curve = require('ed2curve');

const { toBase58, toUint8Array } = ocapUtil;
const hashFn = getHasher(types.HashType.SHA3);
const encoder = new TextEncoder();

/** Fixed test-only wallet material (must match committed JSON). */
const KEYS = {
  senderSecretKeyHex:
    '0x9b835aba9f9a286d184cb039304bc54cb2bb33e61772ebc40520950b0be6d532fe35bf834153c1dc38a1078c282d797b9406701ca3923b187b33847f163736df',
  senderPublicKeyHex: '0xfe35bf834153c1dc38a1078c282d797b9406701ca3923b187b33847f163736df',
  receiverSecretKeyHex:
    '0x111ebcd01676f20096ab0fa26a22677e8a2b4e1bd54660492996c1077a777ef57e3080b0cfeec8ee8ff7500de4e94f8276500072609481320ac74c5282f6aff7',
  receiverPublicKeyHex: '0x7e3080b0cfeec8ee8ff7500de4e94f8276500072609481320ac74c5282f6aff7',
  did: 'z1mMu4gzxyEDDbJ1ART3Mp4p7MSHKTtu3rM',
  receiver: 'z1gSCyDepLvirtxAAg6xR3VBUxaLXLuyPx7',
};

function fromHex(hex) {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  return Uint8Array.from(Buffer.from(h, 'hex'));
}

function encryptWithNonce(content, receiverPublicKey, senderSecretKey, nonce) {
  const contentUint8 = typeof content === 'string' ? encoder.encode(content) : content;
  let pkBytes = toUint8Array(receiverPublicKey);
  const skBytes = toUint8Array(senderSecretKey);
  pkBytes = pkBytes.length === 64 ? pkBytes.slice(0, 32) : pkBytes;
  const pk = ed2curve.convertPublicKey(pkBytes);
  const sk = ed2curve.convertSecretKey(skBytes);
  const encryptedContent = nacl.box(contentUint8, nonce, pk, sk);
  if (!encryptedContent) throw new Error('encrypt failed');
  return new Uint8Array([...nonce, ...encryptedContent]);
}

function decryptBytes(encrypted, senderPublicKey, recipientSecretKey) {
  let pk = toUint8Array(senderPublicKey);
  const sk = toUint8Array(recipientSecretKey);
  pk = pk.length === 64 ? pk.slice(0, 32) : pk;
  const curvePk = ed2curve.convertPublicKey(pk);
  const curveSk = ed2curve.convertSecretKey(sk);
  const nonce = encrypted.slice(0, 24);
  const ct = encrypted.slice(24);
  const opened = nacl.box.open(ct, nonce, curvePk, curveSk);
  if (!opened) throw new Error('decrypt failed');
  return opened;
}

function mailHash(did, receiver, subject, content, envelope, attachments) {
  const parts = [
    ...encoder.encode(did),
    ...encoder.encode(receiver),
    ...subject,
    ...content,
    ...encoder.encode(envelope),
  ];
  for (const a of attachments) {
    parts.push(...encoder.encode(a.id), ...encoder.encode(String(a.size)), ...encoder.encode(a.hash));
  }
  return hashFn(new Uint8Array(parts), 1).slice(-64).toUpperCase();
}

const nonceSubject = new Uint8Array(24).fill(1);
const nonceContent = new Uint8Array(24).fill(2);
const nonceAtt = new Uint8Array(24).fill(3);
const nonceName = new Uint8Array(24).fill(4);
const nonceMime = new Uint8Array(24).fill(5);

const subjectUtf8 = 'hello';
const contentUtf8 = 'world';
const plainHex = '00010203040506070809';
const plain = fromHex(plainHex);
const name = '测试.bin';
const mime = 'application/octet-stream';
const envelope = 'z3CtExampleEnvelopeForAttachmentFixture0001';
const attId = '00000000-0000-4000-8000-000000000001';

const { senderSecretKeyHex, senderPublicKeyHex, receiverSecretKeyHex, receiverPublicKeyHex, did, receiver } =
  KEYS;

const subjectEnc = encryptWithNonce(subjectUtf8, receiverPublicKeyHex, senderSecretKeyHex, nonceSubject);
const contentEnc = encryptWithNonce(contentUtf8, receiverPublicKeyHex, senderSecretKeyHex, nonceContent);
const attEnc = encryptWithNonce(plain, receiverPublicKeyHex, senderSecretKeyHex, nonceAtt);
const nameEnc = encryptWithNonce(name, receiverPublicKeyHex, senderSecretKeyHex, nonceName);
const mimeEnc = encryptWithNonce(mime, receiverPublicKeyHex, senderSecretKeyHex, nonceMime);

if (!Buffer.from(decryptBytes(attEnc, senderPublicKeyHex, receiverSecretKeyHex)).equals(Buffer.from(plain))) {
  throw new Error('attachment plaintext roundtrip failed');
}

const attHash = hashFn(attEnc, 1).slice(-64).toUpperCase();
const expectedSize = plain.length;

const hashWith = mailHash(did, receiver, subjectEnc, contentEnc, envelope, [
  { id: attId, size: expectedSize, hash: attHash },
]);
const hashWithout = mailHash(did, receiver, subjectEnc, contentEnc, envelope, []);

const fixture = {
  version: 1,
  status: 'real',
  generatedAt: new Date().toISOString(),
  notes: [
    'NaCl Box: nonce(24) || ciphertext; ED25519 keys converted via ed2curve (same as extension Box).',
    'Nonces are fixed for determinism (byte fill 1..5); production uses nacl.randomBytes.',
    'expectedContentHash = SHA3-256(encrypted).slice(-64).toUpperCase() via @ocap/mcrypto hashFn(..., 1).',
    'Mail hash uses encrypted subject/content bytes (not plaintext UTF-8).',
    'Base58 key fields are multibase z-prefixed (toBase58 of raw key bytes). Hex fields are 0x-prefixed wallet form.',
    'Keys are test-only; do not use in production.',
  ],
  senderSecretKeyBase58: toBase58(toUint8Array(senderSecretKeyHex)),
  senderPublicKeyBase58: toBase58(toUint8Array(senderPublicKeyHex)),
  receiverSecretKeyBase58: toBase58(toUint8Array(receiverSecretKeyHex)),
  receiverPublicKeyBase58: toBase58(toUint8Array(receiverPublicKeyHex)),
  senderSecretKeyHex,
  senderPublicKeyHex,
  receiverSecretKeyHex,
  receiverPublicKeyHex,
  did,
  receiver,
  envelope,
  subjectUtf8,
  contentUtf8,
  subjectEncryptedHex: Buffer.from(subjectEnc).toString('hex'),
  contentEncryptedHex: Buffer.from(contentEnc).toString('hex'),
  nonces: {
    subject: Buffer.from(nonceSubject).toString('hex'),
    content: Buffer.from(nonceContent).toString('hex'),
    attachment: Buffer.from(nonceAtt).toString('hex'),
    name: Buffer.from(nonceName).toString('hex'),
    mime: Buffer.from(nonceMime).toString('hex'),
  },
  attachments: [
    {
      id: attId,
      plainHex,
      name,
      mime,
      encryptedHex: Buffer.from(attEnc).toString('hex'),
      encryptedNameBase58: toBase58(nameEnc),
      encryptedMimeBase58: toBase58(mimeEnc),
      expectedSize,
      expectedEncryptedLen: attEnc.length,
      expectedContentHash: attHash,
    },
  ],
  expectedMailHashWithAttachments: hashWith,
  expectedMailHashWithoutAttachments: hashWithout,
  downloadSignMessageExample: {
    mailId: '42',
    attachmentId: attId,
    timeStamp: '1699999999999',
    message: `42-${attId}-1699999999999`,
  },
};

const outPath = path.join(__dirname, 'attachment-crypto-vectors.json');
fs.writeFileSync(outPath, `${JSON.stringify(fixture, null, 2)}\n`);
console.log('Wrote', outPath);
console.log({
  expectedEncryptedLen: attEnc.length,
  expectedContentHash: attHash,
  expectedMailHashWithAttachments: hashWith,
  expectedMailHashWithoutAttachments: hashWithout,
});
