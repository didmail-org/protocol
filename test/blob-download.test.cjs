const {test}=require('node:test');
const assert=require('node:assert/strict');
const p=require('../dist/index.cjs');
const seed=new Uint8Array(32).fill(7),peerSeed=new Uint8Array(32).fill(8);
const owner=p.identityId('z'+'a'.repeat(32)),peer=p.identityId('z'+'b'.repeat(32)),service=p.identityId('z'+'c'.repeat(32));
const matches=(pk,id)=>[[owner,seed],[peer,peerSeed]].some(([who,sk])=>id===who&&Buffer.from(pk).equals(Buffer.from(p.signingPublicKey(sk))));
function fixture(){return p.sealMessage({senderId:peer,recipientId:owner,serviceId:service,planId:'fixture',secretKey:peerSeed,senderKey:p.createKeyRecord(peer,peerSeed),recipientKey:p.createKeyRecord(owner,seed),subject:'Public fixture',body:'Authenticated download',matches,attachments:[{fileName:'fixture.bin',mediaType:'application/octet-stream',bytes:new Uint8Array(p.CHUNK_BYTES+1).fill(9)}]});}
function client(transport,id=owner){return new p.DmpClient({endpoint:'https://public-fixture.invalid',identityId:id,secretKey:seed,matches,pinService:async()=>{},store:{put:async()=>{},get:async()=>undefined,remove:async()=>{}},transport});}
for(const mode of ['invalid-proof','unbounded-count','invalid-message-id','invalid-blob-id'])test(`blob rejects ${mode} before dispatch`,async()=>{
 const sealed=fixture();let manifest=structuredClone(sealed.manifest);const blob=manifest.blobs[1];let calls=0;
 if(mode==='invalid-proof')manifest.proof.signature='A'.repeat(86);
 if(mode==='unbounded-count')blob.chunkCount=1000000;
 if(mode==='invalid-message-id')manifest.messageId='../other';
 if(mode==='invalid-blob-id')blob.blobId='../other';
 if(mode!=='invalid-proof')manifest=p.signArtifact('DMP1-MANIFEST',p.unsignedArtifact(manifest),peer,peerSeed);
 const sdk=client(async()=>{calls++;throw new Error('Unexpected dispatch');});
 await assert.rejects(()=>sdk.blob(manifest,blob.blobId));assert.equal(calls,0);
});
test('blob rejects an unrelated authenticated manifest before dispatch',async()=>{
 const sealed=fixture();let calls=0;
 const sdk=client(async()=>{calls++;throw new Error('Unexpected dispatch');},service);
 await assert.rejects(()=>sdk.blob(sealed.manifest,sealed.manifest.documentBlobId),/Missing ciphertext or key/);assert.equal(calls,0);
});
for(const mode of ['wrong-length','wrong-digest'])test(`blob stops at the first ${mode} chunk`,async()=>{
 const sealed=fixture(),blob=sealed.manifest.blobs[1];let calls=0;
 const sdk=client(async()=>{calls++;const bytes=p.unb64u(sealed.chunks[blob.blobId][0]);if(mode==='wrong-length')return {status:200,headers:new Headers(),body:bytes.subarray(1)};bytes[0]^=1;return {status:200,headers:new Headers(),body:bytes};});
 await assert.rejects(()=>sdk.blob(sealed.manifest,blob.blobId),/Ciphertext integrity/);assert.equal(calls,1);
});
test('blob downloads authenticated chunks and preserves historic decryption',async()=>{
 const sealed=fixture(),blob=sealed.manifest.blobs[1];let calls=0;
 const limits=[];
 const sdk=client(async(url,method,headers,body,options)=>{limits.push(options.maxResponseBytes);return {status:200,headers:new Headers(),body:p.unb64u(sealed.chunks[blob.blobId][calls++])};});
 const bytes=await sdk.blob(sealed.manifest,blob.blobId,sealed.manifest.createdAt);
 assert.equal(bytes.length,p.CHUNK_BYTES+1);assert.ok(bytes.every(byte=>byte===9));assert.equal(calls,2);
 assert.deepEqual(limits,[p.CHUNK_BYTES+16,17]);
});
