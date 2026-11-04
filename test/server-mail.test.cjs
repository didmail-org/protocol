const {test}=require('node:test');
const assert=require('node:assert/strict');
const p=require('../dist/index.cjs');
const fixture=require('./fixtures/member-mail.json');
const seeds=fixture.publicTestSeeds.map(n=>new Uint8Array(32).fill(n));
const ids=[fixture.manifest.senderId,fixture.manifest.recipientId,fixture.manifest.serviceId];
const matches=(pk,id)=>ids.some((v,i)=>v===id&&Buffer.from(pk).equals(Buffer.from(p.signingPublicKey(seeds[i]))));
const sign=(domain,value)=>p.signArtifact(domain,value,ids[2],seeds[2]);
const unsigned=x=>{const v=structuredClone(x);delete v.proof;return v;};

test('shared offline credential fixture validates without any chain evidence and decrypts all blobs',()=>{
  const {manifest,receipt,quote,chunks}=fixture;
  p.validateServerQuote(quote,manifest,matches,Date.parse(quote.issuedAt)+1);
  p.validateServerReceipt(receipt,manifest,matches);
  assert.equal(receipt.termsSha256,p.termsHash(quote));
  assert.throws(()=>p.validateReceiptChainEvidence(receipt));
  const bytes=p.decryptBlob(manifest,manifest.documentBlobId,chunks[manifest.documentBlobId].map(x=>p.unb64u(x)),ids[1],seeds[1],matches,receipt.acceptedAt);
  const document=p.decodeDocument(bytes);assert.equal(document.subject,'Public internal fixture');
  const id=document.attachments[0].blobId;
  assert.deepEqual([...p.decryptBlob(manifest,id,chunks[id].map(x=>p.unb64u(x)),ids[1],seeds[1],matches,receipt.acceptedAt)],[1,2,3]);
});

test('even service-signed internal terms cannot add charges or omit explicit authorization',()=>{
  for(const change of [{totalAmount:'1'},{indexAmount:'1'},{funding:{mode:'node-sponsored',sponsorId:ids[2],amount:'1'}},{delivery:undefined},{policyRevision:0},{memberBindings:{senderRevision:0,recipientRevision:1}},{extra:'ignored?'}]){
    const value={...unsigned(fixture.quote),...change};for(const k of Object.keys(value))if(value[k]===undefined)delete value[k];
    const bad=sign('DMP1-QUOTE',value);
    assert.throws(()=>p.validateServerQuote(bad,fixture.manifest,matches,Date.parse(fixture.quote.issuedAt)+1));
  }
  assert.throws(()=>p.validateServerQuote(fixture.quote,{...fixture.manifest,automaticDelivery:undefined},matches,Date.parse(fixture.quote.issuedAt)+1));
});

test('offline receipts reject payment/NFT fields, foreign recipients, time conflicts and signature tampering',()=>{
  for(const change of [{index:{assetId:'fake'}},{payment:{}},{funding:{}},{recipientId:ids[0]},{termsSha256:'bad'},{retentionExpiresAt:fixture.receipt.deliveredAt},{extra:true}]){
    assert.throws(()=>p.validateServerReceipt(sign('DMP1-RECEIPT',{...unsigned(fixture.receipt),...change}),fixture.manifest,matches));
  }
  assert.throws(()=>p.validateServerReceipt({...fixture.receipt,deliveredAt:'2030-01-01T00:00:00.000Z'},fixture.manifest,matches));
});
