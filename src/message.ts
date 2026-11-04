import { b64u,unb64u,utf8,text,concat,digest,canonicalize,uuid,isUuid,isDigest,addressOf } from './codec';
import { CRYPTO_SUITE,signArtifact,verifyArtifact,unsignedArtifact,blobKey,encryptChunk,decryptChunk,hpkeSeal,hpkeOpen,recoveryEncryptionSecret,encryptionPublicKey,keyIdOf,type IdentityMatcher } from './crypto';
import type { KeyRecord, KeyRevocation, Manifest, SealedMessage, EmailDocument, BlobDescriptor } from './types';
import { randomBytes } from './codec';
export const CHUNK_BYTES=1024*1024;
export type EncryptionManifest = Omit<Manifest,'protocolVersion'> & {protocolVersion:1|2};
// Creation timestamps tolerate the same bounded drift as protocol requests.
// Expiry remains exclusive; this allowance never extends a key lifetime.
export const KEY_RECORD_CLOCK_SKEW_MS=30_000;
export function expectKeys(value:unknown,keys:string[]): asserts value is Record<string,unknown> {
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!==[...keys].sort().join(',')) throw new Error('Invalid object members');
}
export function validTimestamp(value:unknown): value is string { return typeof value==='string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString()===value; }
export function createKeyRecord(ownerId:string,secret:Uint8Array,now=new Date()):KeyRecord {
  const encryptionSecret=recoveryEncryptionSecret(secret);
  try{return createDeviceKeyRecord(ownerId,secret,encryptionSecret,now);}finally{encryptionSecret.fill(0);}
}
/** Sign a public device record. Persist its random private key before publishing. */
export function createDeviceKeyRecord(ownerId:string,secret:Uint8Array,encryptionSecret:Uint8Array,now=new Date()):KeyRecord {
  if(!(encryptionSecret instanceof Uint8Array)||encryptionSecret.length!==32)throw new Error('Invalid device encryption secret');
  const publicKey=encryptionPublicKey(encryptionSecret);
  return signArtifact('DMP1-KEY-RECORD',{protocolVersion:1 as const,ownerId,keyId:keyIdOf(publicKey),cryptoSuite:CRYPTO_SUITE,publicKey:b64u(publicKey),createdAt:now.toISOString(),expiresAt:new Date(now.getTime()+365*86400000).toISOString()},ownerId,secret);
}
export function validateKeyRecord(record:KeyRecord,matches:IdentityMatcher,atTime=Date.now()):void {
  expectKeys(record,['protocolVersion','ownerId','keyId','cryptoSuite','publicKey','createdAt','expiresAt','proof']);
  addressOf(record.ownerId);
  const created=Date.parse(record.createdAt),expires=Date.parse(record.expiresAt);
  if(!Number.isSafeInteger(atTime)||record.protocolVersion!==1||record.cryptoSuite!==CRYPTO_SUITE||record.keyId!==keyIdOf(unb64u(record.publicKey,32))||!validTimestamp(record.createdAt)||!validTimestamp(record.expiresAt)||created>atTime+KEY_RECORD_CLOCK_SKEW_MS||expires<=atTime||expires<=created||expires-created>366*86400000||!verifyArtifact('DMP1-KEY-RECORD',record,record.ownerId,matches)) throw new Error('Invalid or expired encryption key record');
}
export function validateKeyRevocation(value:KeyRevocation,matches:IdentityMatcher,atTime=Date.now()):void {
  expectKeys(value,['protocolVersion','ownerId','keyId','revokedAt','reason','proof']);addressOf(value.ownerId);
  if(!Number.isSafeInteger(atTime)||value.protocolVersion!==1||!isDigest(value.keyId)||!validTimestamp(value.revokedAt)||Date.parse(value.revokedAt)>atTime+KEY_RECORD_CLOCK_SKEW_MS||!['rotated','compromised','retired'].includes(value.reason)||!verifyArtifact('DMP1-KEY-REVOCATION',value,value.ownerId,matches))throw new Error('Invalid encryption key revocation');
}
export function manifestHash(manifest:Manifest):string { return digest(utf8(canonicalize(unsignedArtifact(manifest)))); }
export function validateManifest(manifest:Manifest,matches:IdentityMatcher,atTime=Date.parse(manifest.createdAt)):void {
  validateManifestVersion(manifest,1,matches,atTime);
}
export function validateManifestVersion(manifest:EncryptionManifest,version:1|2,matches:IdentityMatcher,atTime=Date.parse(manifest.createdAt)):void {
  expectKeys(manifest,['protocolVersion','messageId','senderId','recipientId','serviceId','createdAt','planId','cryptoSuite','keyEnvelopes','documentBlobId','blobs','proof',...(manifest.automaticDelivery===undefined?[]:['automaticDelivery'])]);
  if(manifest.automaticDelivery!==undefined&&manifest.automaticDelivery!==true)throw new Error('Invalid automatic delivery extension');
  addressOf(manifest.senderId);addressOf(manifest.recipientId);addressOf(manifest.serviceId);
  if(manifest.protocolVersion!==version||manifest.cryptoSuite!==CRYPTO_SUITE||!isUuid(manifest.messageId)||!isUuid(manifest.documentBlobId)||!validTimestamp(manifest.createdAt)||typeof manifest.planId!=='string'||manifest.planId.length>128||!manifest.planId||!verifyArtifact(`DMP${version}-MANIFEST`,manifest,manifest.senderId,matches)) throw new Error('Invalid message manifest');
  const owners=manifest.senderId===manifest.recipientId?[manifest.senderId]:[manifest.senderId,manifest.recipientId];
  if(!Array.isArray(manifest.keyEnvelopes)||manifest.keyEnvelopes.length!==owners.length) throw new Error('Missing key envelope');
  const seenOwners=new Set<string>();
  for(const key of manifest.keyEnvelopes) {
    expectKeys(key,['ownerId','keyId','keyRecord','encapsulatedKey','ciphertext']);
    if(!owners.includes(key.ownerId)||seenOwners.has(key.ownerId)||key.keyRecord.ownerId!==key.ownerId||key.keyRecord.keyId!==key.keyId) throw new Error('Key envelope owner mismatch');
    validateKeyRecord(key.keyRecord,matches,atTime);unb64u(key.encapsulatedKey,32);unb64u(key.ciphertext,48);seenOwners.add(key.ownerId);
  }
  if(!Array.isArray(manifest.blobs)||manifest.blobs.length<1||manifest.blobs.length>21) throw new Error('Invalid blob count');
  const ids=new Set<string>();let total=0;
  for(const blob of manifest.blobs) {
    expectKeys(blob,['blobId','sizeBytes','chunkCount','ciphertextSha256','chunkSha256']);
    if(!isUuid(blob.blobId)||ids.has(blob.blobId)||!Number.isSafeInteger(blob.sizeBytes)||!Number.isSafeInteger(blob.chunkCount)||blob.chunkCount<1||blob.chunkCount>65||!isDigest(blob.ciphertextSha256)||!Array.isArray(blob.chunkSha256)||blob.chunkSha256.length!==blob.chunkCount||blob.chunkSha256.some(h=>!isDigest(h))) throw new Error('Invalid blob descriptor');
    const final=blob.sizeBytes-(blob.chunkCount-1)*(CHUNK_BYTES+16);
    if(final<16||final>CHUNK_BYTES+16||(blob.chunkCount>1&&final===16)) throw new Error('Invalid chunk length');
    if(blob.blobId===manifest.documentBlobId && blob.sizeBytes>256*1024+16) throw new Error('Document too large');
    total+=blob.sizeBytes;ids.add(blob.blobId);
  }
  if(!ids.has(manifest.documentBlobId)||total>64*1024*1024) throw new Error('Invalid message size or document');
}
export function chunkSize(blob:BlobDescriptor,index:number):number {
  if(!Number.isSafeInteger(index)||index<0||index>=blob.chunkCount) throw new Error('Invalid chunk index');
  return index===blob.chunkCount-1?blob.sizeBytes-(blob.chunkCount-1)*(CHUNK_BYTES+16):CHUNK_BYTES+16;
}
export interface PlainAttachment { fileName:string; mediaType:string; bytes:Uint8Array }
export function sealEncryptedMessage(input:{senderId:string;recipientId:string;serviceId:string;planId:string;secretKey:Uint8Array;senderKey:KeyRecord;recipientKey:KeyRecord;subject:string;body:string;mediaType?:'text/plain'|'text/html';attachments?:PlainAttachment[];automaticDelivery?:true;matches:IdentityMatcher},version:1|2):{manifest:EncryptionManifest;chunks:Record<string,string[]>} {
  if(input.senderKey.ownerId!==input.senderId||input.recipientKey.ownerId!==input.recipientId) throw new Error('Encryption identity mismatch');
  validateKeyRecord(input.senderKey,input.matches);validateKeyRecord(input.recipientKey,input.matches);
  const messageId=uuid(),contentKey=randomBytes(32),documentBlobId=uuid();
  const descriptors:BlobDescriptor[]=[],chunks:Record<string,string[]>={};
  const attachments=(input.attachments||[]).map(a=>({...a,blobId:uuid()}));
  const document:EmailDocument={contentType:'email',subject:input.subject,body:{mediaType:input.mediaType||'text/html',text:input.body},attachments:attachments.map(a=>({blobId:a.blobId,fileName:a.fileName,mediaType:a.mediaType,sizeBytes:a.bytes.length}))};
  const addBlob=(blobId:string,plain:Uint8Array) => {
    const count=Math.max(1,Math.ceil(plain.length/CHUNK_BYTES)), key=blobKey(contentKey,messageId,blobId),encrypted:Uint8Array[]=[];
    for(let index=0;index<count;index++) encrypted.push(encryptChunk(key,messageId,blobId,index,count,plain.subarray(index*CHUNK_BYTES,(index+1)*CHUNK_BYTES)));
    chunks[blobId]=encrypted.map(b64u);
    descriptors.push({blobId,sizeBytes:encrypted.reduce((sum,c)=>sum+c.length,0),chunkCount:count,ciphertextSha256:digest(concat(...encrypted)),chunkSha256:encrypted.map(digest)});
  };
  try {
    addBlob(documentBlobId,utf8(canonicalize(document)));
    for(const file of attachments) addBlob(file.blobId,file.bytes);
    const records=input.senderId===input.recipientId?[input.recipientKey]:[input.senderKey,input.recipientKey];
    const keyEnvelopes=records.map(record=>({ownerId:record.ownerId,keyId:record.keyId,keyRecord:record,...hpkeSeal(unb64u(record.publicKey,32),utf8(`DMP1-KEY\n${messageId}\n${record.ownerId}\n${record.keyId}`),contentKey)}));
    const manifest=signArtifact(`DMP${version}-MANIFEST`,{protocolVersion:version,messageId,senderId:input.senderId,recipientId:input.recipientId,serviceId:input.serviceId,createdAt:new Date().toISOString(),planId:input.planId,...(input.automaticDelivery?{automaticDelivery:true as const}:{}),cryptoSuite:CRYPTO_SUITE,keyEnvelopes,documentBlobId,blobs:descriptors},input.senderId,input.secretKey);
    validateManifestVersion(manifest,version,input.matches);return {manifest,chunks};
  } finally {contentKey.fill(0);}
}
export function decryptEncryptedBlob(manifest:EncryptionManifest,version:1|2,blobId:string,chunks:Uint8Array[],ownerId:string,secretKey:Uint8Array,matches:IdentityMatcher,acceptedAt?:string,encryptionSecret?:Uint8Array):Uint8Array {
  validateManifestVersion(manifest,version,matches,Date.parse(acceptedAt||manifest.createdAt));
  const desc=manifest.blobs.find(b=>b.blobId===blobId),envelope=manifest.keyEnvelopes.find(k=>k.ownerId===ownerId);
  if(!desc||!envelope||chunks.length!==desc.chunkCount) throw new Error('Missing ciphertext or key');
  for(let i=0;i<chunks.length;i++) if(chunks[i].length!==chunkSize(desc,i)||digest(chunks[i])!==desc.chunkSha256[i]) throw new Error('Ciphertext integrity failure');
  if(digest(concat(...chunks))!==desc.ciphertextSha256) throw new Error('Blob digest mismatch');
  const secret=encryptionSecret===undefined?recoveryEncryptionSecret(secretKey):new Uint8Array(encryptionSecret);
  let contentKey:Uint8Array|undefined,key:Uint8Array|undefined;
  try {
    if(secret.length!==32||keyIdOf(encryptionPublicKey(secret))!==envelope.keyId) throw new Error('Historic private key required');
    contentKey=hpkeOpen(secret,unb64u(envelope.encapsulatedKey,32),utf8(`DMP1-KEY\n${manifest.messageId}\n${ownerId}\n${envelope.keyId}`),unb64u(envelope.ciphertext,48));
    key=blobKey(contentKey,manifest.messageId,blobId);return concat(...chunks.map((c,i)=>decryptChunk(key!,manifest.messageId,blobId,i,desc.chunkCount,c)));
  } finally {key?.fill(0);contentKey?.fill(0);secret.fill(0);}
}
export function decodeDocument(bytes:Uint8Array):EmailDocument {
  const d=JSON.parse(text(bytes)) as EmailDocument;
  if(d.contentType!=='email'||typeof d.subject!=='string'||!d.body||!['text/plain','text/html'].includes(d.body.mediaType)||typeof d.body.text!=='string'||!Array.isArray(d.attachments)) throw new Error('Invalid email document');
  return d;
}

export function sealMessage(input:Parameters<typeof sealEncryptedMessage>[0]):SealedMessage {
  return sealEncryptedMessage(input,1) as SealedMessage;
}
export function decryptBlob(manifest:Manifest,blobId:string,chunks:Uint8Array[],ownerId:string,secretKey:Uint8Array,matches:IdentityMatcher,acceptedAt?:string,encryptionSecret?:Uint8Array):Uint8Array {
  return decryptEncryptedBlob(manifest,1,blobId,chunks,ownerId,secretKey,matches,acceptedAt,encryptionSecret);
}
