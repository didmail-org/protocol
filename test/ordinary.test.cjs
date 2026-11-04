const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const p=require('../dist/index.cjs');
const f=JSON.parse(fs.readFileSync(path.join(__dirname,'../docs/protocol/dmp-2/fixtures/ordinary-vc.json'),'utf8'));
const secret=name=>Uint8Array.from(Buffer.from(f.secretKeys[name].replace(/^0x/,''),'hex'));
const keys=new Map([[f.manifest.senderId,p.signingPublicKey(secret('sender'))],[f.manifest.recipientId,p.signingPublicKey(secret('recipient'))],[f.manifest.serviceId,p.signingPublicKey(secret('service'))]]);
const matches=(pk,did)=>keys.has(did)&&Buffer.from(pk).equals(Buffer.from(keys.get(did)));
const at=Date.parse(f.receipt.acceptedAt);
test('ordinary manifest, ArcBlock SDK VC, terms and free receipt validate without NFT or payment evidence',()=>{
 p.validateOrdinaryManifest(f.manifest,matches,at);p.validateOrdinaryTerms(f.terms,f.manifest,matches,at);
 p.validateOrdinaryCredential(f.credential,f.manifest,f.terms,f.endpoint,matches);p.validateOrdinaryReceipt(f.receipt,f.manifest,f.terms,f.credential,matches);
 assert.equal('index' in f.receipt,false);assert.deepEqual(f.receipt.payment,{mode:'none'});
 const bytes=p.decryptOrdinaryBlob(f.manifest,f.manifest.documentBlobId,f.chunks[f.manifest.documentBlobId].map(v=>p.unb64u(v)),f.manifest.recipientId,secret('recipient'),matches,f.receipt.acceptedAt);
 const document=p.decodeDocument(bytes);assert.equal(document.subject,'普通邮件 / Résumé 👋');
 assert.deepEqual(p.decryptOrdinaryBlob(f.manifest,document.attachments[0].blobId,f.chunks[document.attachments[0].blobId].map(v=>p.unb64u(v)),f.manifest.recipientId,secret('recipient'),matches,f.receipt.acceptedAt),Uint8Array.from([0,255,128,1]));
});
test('DMP versions cannot be interchanged despite reuse of body encryption',()=>{
 assert.throws(()=>p.validateManifest(f.manifest,matches,at));
 const downgrade=p.signArtifact('DMP1-MANIFEST',{...p.unsignedArtifact(f.manifest),protocolVersion:1},f.manifest.senderId,secret('sender'));
 assert.throws(()=>p.validateOrdinaryManifest(downgrade,matches,at));
 assert.throws(()=>p.decryptBlob(f.manifest,f.manifest.documentBlobId,f.chunks[f.manifest.documentBlobId].map(v=>p.unb64u(v)),f.manifest.recipientId,secret('recipient'),matches,f.receipt.acceptedAt));
});
test('VC rejects cross-node, cross-recipient, endpoint tamper, extra members and invalid proof metadata',()=>{
 for(const mutate of [v=>v.credentialSubject.id=p.addressOf(f.manifest.senderId),v=>v.credentialSubject.endpoint='https://attacker.example',v=>v.credentialSubject.termsSha256='a'.repeat(64),v=>v.issuer.id=p.addressOf(f.manifest.senderId),v=>v.proof.proofPurpose='authentication',v=>v.credentialSubject.subject='public secret',v=>v.expirationDate='2099-01-01T00:00:00.000Z']){
  const changed=structuredClone(f.credential);mutate(changed);assert.throws(()=>p.validateOrdinaryCredential(changed,f.manifest,f.terms,f.endpoint,matches));
 }
 assert.throws(()=>p.validateOrdinaryCredential(f.credential,f.manifest,f.terms,'https://another.example',matches));
});
test('signed free terms and receipts reject hidden payment, retention changes, mismatched evidence and expired acceptance',()=>{
 for(const mutate of [v=>v.totalAmount='1',v=>v.settlement={profile:'arcblock-transfer-v3-mail-nft/1'},v=>v.limits.maxCount=21,v=>v.notification.chainEndpoint='https://user:pass@chain.test/api/',v=>v.retentionSeconds=0]){
  const value=structuredClone(p.unsignedArtifact(f.terms));mutate(value);assert.throws(()=>p.validateOrdinaryTerms(p.signOrdinaryTerms(value,secret('service')),f.manifest,matches,at));
 }
 assert.throws(()=>p.validateOrdinaryTerms(f.terms,f.manifest,matches,Date.parse(f.terms.expiresAt)));
 for(const mutate of [v=>v.payment={mode:'none',transactionId:'B'.repeat(64)},v=>v.retentionExpiresAt='2099-01-01T00:00:00.000Z',v=>v.notification.transaction.chainId='main',v=>v.notification.transaction.blockHeight='1',v=>v.acceptedAt=f.terms.expiresAt]){
  const value=structuredClone(p.unsignedArtifact(f.receipt));mutate(value);const changed=p.signArtifact('DMP2-RECEIPT',value,f.manifest.serviceId,secret('service'));assert.throws(()=>p.validateOrdinaryReceipt(changed,f.manifest,f.terms,f.credential,matches));
 }
});

test('chain inbox finds another node from a signed VC and isolates malformed notifications',()=>{
 const recipientId=f.manifest.recipientId,serviceId=f.manifest.serviceId;
 const query=p.ordinaryInboxRequest(recipientId,'0',50);assert.equal(query.variables.receiver,p.addressOf(recipientId));
 const row={hash:'A'.repeat(64),code:'OK',valid:true,sender:p.addressOf(serviceId),receiver:p.addressOf(recipientId),tx:{from:p.addressOf(serviceId),chainId:'beta',itxJson:{type_url:'fg:t:transfer_v2',data:{typeUrl:'vc',value:f.credential}}}};
 const response={data:{listTransactions:{code:'OK',page:{cursor:'1',next:false,total:1},transactions:[row]}}};
 const options={recipientId,chainId:'beta',cursor:'0',limit:50,matches};
 const result=p.parseOrdinaryInboxPage(response,options);assert.equal(result.candidates[0].endpoint,f.endpoint);assert.equal(result.candidates[0].transactionId,f.receipt.notification.transaction.transactionId);assert.equal(result.nextCursor,null);
 const malicious=structuredClone(row);malicious.hash='B'.repeat(64);malicious.tx.itxJson.data.value.credentialSubject.endpoint='https://attacker.example';
 const page=p.parseOrdinaryInboxPage({data:{listTransactions:{...response.data.listTransactions,transactions:[row,malicious],page:{cursor:'2',next:false,total:2}}}},options);
 assert.equal(page.candidates.length,1);assert.deepEqual(page.invalidTransactions,['B'.repeat(64)]);
 for(const change of [r=>r.receiver=p.addressOf(f.manifest.senderId),r=>r.tx.chainId='main',r=>r.sender=p.addressOf(f.manifest.senderId)]){
  const bad=structuredClone(row);change(bad);assert.equal(p.parseOrdinaryInboxPage({data:{listTransactions:{...response.data.listTransactions,transactions:[bad]}}},options).candidates.length,0);
 }
 assert.throws(()=>p.parseOrdinaryInboxPage({data:{listTransactions:{...response.data.listTransactions,page:{cursor:'0',next:true,total:1}}}},options));
 assert.throws(()=>p.ordinaryInboxRequest(recipientId,'0',101));
});
test('compact on-chain VC round trips the exact signed credential and binds outer identities and key',()=>{
 const packed=p.packOrdinaryCredential(f.credential),context={sender:p.addressOf(f.manifest.serviceId),recipient:p.addressOf(f.manifest.recipientId),publicKey:keys.get(f.manifest.serviceId),matches};
 assert.deepEqual(p.unpackOrdinaryCredential(packed,context),f.credential);
 assert.ok(p.utf8(p.canonicalize(packed)).length<450);
 for(const mutate of [v=>v.dmp2vc.push('extra'),v=>v.dmp2vc[0]=2,v=>v.dmp2vc[3]='A'.repeat(43),v=>v.dmp2vc[5]='https://attacker.example',v=>v.extra=true]){const value=structuredClone(packed);mutate(value);assert.throws(()=>p.unpackOrdinaryCredential(value,context));}
 assert.throws(()=>p.unpackOrdinaryCredential(packed,{...context,recipient:p.addressOf(f.manifest.senderId)}));
 assert.throws(()=>p.unpackOrdinaryCredential(packed,{...context,publicKey:keys.get(f.manifest.senderId)}));
 const row={hash:'D'.repeat(64),code:'OK',valid:true,sender:context.sender,receiver:context.recipient,tx:{from:context.sender,pk:p.b64u(context.publicKey),chainId:'beta',itxJson:{type_url:'fg:t:transfer_v2',to:context.recipient,data:{typeUrl:'json',value:packed}}}};
 const result=p.parseOrdinaryInboxPage({data:{listTransactions:{code:'OK',page:{cursor:'1',next:false},transactions:[row]}}},{recipientId:f.manifest.recipientId,chainId:'beta',cursor:'0',limit:50,matches});assert.equal(result.candidates.length,1);assert.deepEqual(result.candidates[0].credential,f.credential);
});

test('collection protobuf fallback discovers a compact VC when the RPC omits decoded Any data',()=>{
 const v=JSON.parse(fs.readFileSync(path.join(__dirname,'../docs/protocol/dmp-2/fixtures/ordinary-vc-compact.json'),'utf8'));
 const decoded=p.decodeOrdinaryTransferV2Data(v.encodedInnerTransfer);assert.equal(decoded.to,v.recipient);assert.deepEqual(decoded.data.value,v.packed);assert.equal(decoded.data.typeUrl,'json');
 const row={hash:'E'.repeat(64),code:'OK',valid:true,sender:v.sender,receiver:v.recipient,tx:{from:v.sender,pk:v.publicKey,chainId:'beta',itxJson:{type_url:'fg:t:transfer_v2',to:v.recipient,encoded_value:v.encodedInnerTransfer}}};
 const options={recipientId:f.manifest.recipientId,chainId:'beta',cursor:'0',limit:50,matches},response={data:{listTransactions:{code:'OK',page:{cursor:'1',next:false},transactions:[row]}}};
 assert.deepEqual(p.parseOrdinaryInboxPage(response,options).candidates[0].credential,v.credential);
 for(const encoded of [v.encodedInnerTransfer.slice(0,10), 'AA==', 'not base64!',Buffer.from([10,128,0]).toString('base64')])assert.throws(()=>p.decodeOrdinaryTransferV2Data(encoded));
 row.tx.itxJson.to=v.sender;assert.equal(p.parseOrdinaryInboxPage(response,options).candidates.length,0);
});
