const {test}=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');const crypto=require('node:crypto');
const p=require('../dist/index.cjs');
const vector=JSON.parse(fs.readFileSync(path.join(__dirname,'../docs/protocol/dmp-1/fixtures/hpke-rfc9180.json'))).vector;
const bytes=h=>Uint8Array.from(Buffer.from(h,'hex'));
const alice=p.identityId('z'+'a'.repeat(32)),bob=p.identityId('z'+'b'.repeat(32)),service=p.identityId('z'+'c'.repeat(32));
const a=new Uint8Array(32).fill(7),b=new Uint8Array(32).fill(9),s=new Uint8Array(32).fill(11);
const keys=new Map([[alice,p.signingPublicKey(a)],[bob,p.signingPublicKey(b)],[service,p.signingPublicKey(s)]]);
const matches=(pk,did)=>keys.has(did)&&Buffer.from(pk).equals(Buffer.from(keys.get(did)));
const ak=p.createKeyRecord(alice,a),bk=p.createKeyRecord(bob,b);
function sealed(extra={}){return p.sealMessage({senderId:alice,recipientId:bob,serviceId:service,planId:'zPlan',secretKey:a,senderKey:ak,recipientKey:bk,subject:'会议 / Résumé / العربية 👋',body:'<p>Hello 世界</p>',matches,...extra});}
test('HPKE RFC9180 official base mode vector: exact enc and first three ciphertexts',()=>{
 for(let i=0;i<vector.encryptions.length;i++){
  const e=vector.encryptions[i];const result=p.hpkeSealWithEphemeral(bytes(vector.pkRm),bytes(vector.info),bytes(e.pt),bytes(vector.skEm),bytes(e.aad),i);
  assert.equal(Buffer.from(p.unb64u(result.encapsulatedKey)).toString('hex'),vector.enc);
  assert.equal(Buffer.from(p.unb64u(result.ciphertext)).toString('hex'),e.ct);
 }
});
test('HPKE content-key wrapping rejects wrong key and tamper',()=>{
 const sk=p.recoveryEncryptionSecret(b),pk=p.encryptionPublicKey(sk),info=p.utf8('dmp-test'),plain=p.randomBytes(32),sealed=p.hpkeSeal(pk,info,plain);
 assert.deepEqual(p.hpkeOpen(sk,p.unb64u(sealed.encapsulatedKey),info,p.unb64u(sealed.ciphertext)),plain);
 assert.throws(()=>p.hpkeOpen(p.recoveryEncryptionSecret(a),p.unb64u(sealed.encapsulatedKey),info,p.unb64u(sealed.ciphertext)));
 const bad=p.unb64u(sealed.ciphertext);bad[0]^=1;assert.throws(()=>p.hpkeOpen(sk,p.unb64u(sealed.encapsulatedKey),info,bad));
});
test('JCS sorts UTF16 keys, preserves Unicode, rejects ambiguous/unsafe input',()=>{
 assert.equal(p.canonicalize({z:2,a:'世界',b:[true,null,1e-7]}),'{"a":"世界","b":[true,null,1e-7],"z":2}');
 for(const input of ['{"a":1,"a":2}','{"b":1,"a":2}','{ "a":1}','{"x":9007199254740993}'])assert.throws(()=>p.parseCanonical(p.utf8(input)));
 for(const invalid of [NaN,Infinity,undefined,{x:'\ud800'},JSON.parse('{"__proto__":{}}')])assert.throws(()=>p.canonicalize(invalid));
});
test('RFC9421 request profile covers target/query/digest/identity/time',()=>{
 const url='https://mail.example/v1/messages?cursor=x%2fy&a=1&a=2',body=p.utf8('{"x":1}'),now=1792965600;
 const headers=p.signRequest('PUT',url,body,alice,a,{nowSeconds:now,nonce:'550e8400-e29b-41d4-a716-446655440001'});
 assert.equal(p.verifyRequest('PUT',url,body,new Headers(headers),matches,now).identityId,alice);
 assert.throws(()=>p.verifyRequest('POST',url,body,new Headers(headers),matches,now));
 assert.throws(()=>p.verifyRequest('PUT',url.replace('%2f','%2F'),body,new Headers(headers),matches,now));
 assert.throws(()=>p.verifyRequest('PUT',url,p.utf8('{"x":2}'),new Headers(headers),matches,now));
 assert.throws(()=>p.verifyRequest('PUT',url,body,new Headers(headers),matches,now+91));
 const bad=new Headers(headers);bad.set('dmp-identity',bob);assert.throws(()=>p.verifyRequest('PUT',url,body,bad,matches,now));
 const duplicate=new Headers(headers);duplicate.append('signature-input',headers['signature-input']);assert.throws(()=>p.verifyRequest('PUT',url,body,duplicate,matches,now));
});
test('27 KiB attachment and UTF8 document decrypt for recipient and sender archive',()=>{
 const attachment=p.randomBytes(27*1024);const {manifest,chunks}=sealed({attachments:[{fileName:'机密 résumé.bin',mediaType:'application/octet-stream',bytes:attachment}]});p.validateManifest(manifest,matches);
 const decode=blobId=>chunks[blobId].map(value=>p.unb64u(value));
 const doc=p.decodeDocument(p.decryptBlob(manifest,manifest.documentBlobId,decode(manifest.documentBlobId),bob,b,matches));
 assert.equal(doc.subject,'会议 / Résumé / العربية 👋');assert.equal(doc.attachments[0].fileName,'机密 résumé.bin');
 const id=doc.attachments[0].blobId;
 assert.deepEqual(p.decryptBlob(manifest,id,decode(id),bob,b,matches),attachment);
 assert.deepEqual(p.decryptBlob(manifest,id,decode(id),alice,a,matches),attachment);
 assert.ok(!p.canonicalize(manifest).includes('résumé.bin'));assert.ok(!p.canonicalize(manifest).includes('会议'));
 assert.throws(()=>p.decryptBlob(manifest,id,decode(id),bob,a,matches));
});
test('multi-chunk reordering, truncation, cross-message and manifest tamper fail closed',()=>{
 const {manifest,chunks}=sealed({attachments:[{fileName:'large.bin',mediaType:'application/octet-stream',bytes:p.randomBytes(p.CHUNK_BYTES+200)}]});const blob=manifest.blobs[1],cipher=chunks[blob.blobId].map(v=>p.unb64u(v));
 assert.equal(cipher.length,2);assert.equal(p.decryptBlob(manifest,blob.blobId,cipher,bob,b,matches).length,p.CHUNK_BYTES+200);
 assert.throws(()=>p.decryptBlob(manifest,blob.blobId,[cipher[1],cipher[0]],bob,b,matches));
 assert.throws(()=>p.decryptBlob(manifest,blob.blobId,[cipher[0]],bob,b,matches));
 const bad=structuredClone(manifest);bad.recipientId=alice;assert.throws(()=>p.validateManifest(bad,matches));
 const other=sealed().manifest;assert.throws(()=>p.decryptBlob(other,blob.blobId,cipher,bob,b,matches));
});
test('amounts preserve final smallest unit; malformed encodings and IDs are rejected',()=>{
 assert.equal(p.amount('1000000000000000001')+p.amount('2'),1000000000000000003n);
 for(const value of ['1.0','01','-1',1])assert.throws(()=>p.amount(value));
 for(const value of ['YQ==','YQ+','A'])assert.throws(()=>p.unb64u(value));
 assert.equal(p.isUuid(p.uuid()),true);
});
test('transaction hash conformance: ArcBlock tx ID is uppercase SHA256, distinct from manifest digest',()=>{
 const input=p.utf8('signed protobuf fixture');assert.equal(p.digest(input).toUpperCase(),crypto.createHash('sha256').update(input).digest('hex').toUpperCase());
 assert.notEqual(p.digest(input),crypto.createHash('sha3-256').update(input).digest('hex'));
});
