const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const p=require('../dist/index.cjs');
const f=JSON.parse(fs.readFileSync(path.join(__dirname,'../docs/protocol/dmp-2/fixtures/ordinary-vc.json'),'utf8'));
const secret=name=>Uint8Array.from(Buffer.from(f.secretKeys[name].replace(/^0x/,''),'hex'));
const keys=new Map(['sender','recipient','service'].map(n=>[f.manifest[n==='service'?'serviceId':n+'Id'],p.signingPublicKey(secret(n))]));
const matches=(pk,id)=>keys.has(id)&&Buffer.from(pk).equals(Buffer.from(keys.get(id)));
const candidate={transactionId:f.receipt.notification.transaction.transactionId,endpoint:f.endpoint,serviceId:f.manifest.serviceId,messageId:f.manifest.messageId,manifestSha256:p.ordinaryManifestHash(f.manifest),termsSha256:p.ordinaryTermsHash(f.terms),credential:f.credential};
const config={protocolVersion:2,experimental:true,available:false,policyRevision:f.terms.policyRevision,serviceId:f.manifest.serviceId,apiBaseUrl:f.endpoint+'/v2/ordinary',signingKey:{publicKey:p.b64u(keys.get(f.manifest.serviceId)),keyId:p.keyIdOf(keys.get(f.manifest.serviceId)),serviceId:f.manifest.serviceId},plan:{planId:'ordinary',totalAmount:'0',retentionSeconds:f.terms.retentionSeconds},notification:f.terms.notification,limits:f.terms.limits};
function setup(owner='recipient',alter=x=>x){
 const stored=new Map(),calls=[];let lost=false;
 const store={put:async t=>stored.set(t.manifest.messageId,structuredClone(t)),get:async id=>structuredClone(stored.get(id)),remove:async id=>stored.delete(id)};
 const options={endpoint:f.endpoint,identityId:f.manifest[owner+'Id'],secretKey:secret(owner),matches,store,pinService:async()=>{},transport:async(url,method,headers,body)=>{
   calls.push({url,method,body:Buffer.from(body).toString(),headers});let value;
   if(url.endsWith('/service-config'))value=config;
   else if(url.endsWith('/sending-eligibility'))value={gas:{minimumUnits:'1000000000000000000',node:{eligible:true},sender:{eligible:false}}};
   else if(url.includes('/chunks/'))return{status:200,headers:new Headers(),body:p.unb64u(f.chunks[url.split('/blobs/')[1].split('/')[0]][Number(url.split('/').pop())])};
   else if(url.endsWith('/submit')){assert.deepEqual(JSON.parse(Buffer.from(body).toString()),stored.get(f.manifest.messageId).acceptance);lost=true;throw new Error('response lost');}
   else if(url.endsWith('/status')){assert.equal(lost,true);value={messageId:f.manifest.messageId,state:'queued',revision:2,acceptedAt:f.receipt.acceptedAt,updatedAt:f.receipt.acceptedAt};}
   else value={manifest:f.manifest,terms:f.terms,receipt:f.receipt,credential:f.credential};
   return{status:200,headers:new Headers(),body:p.utf8(p.canonicalize(alter(structuredClone(value))))};
 }};
 return{client:new p.OrdinaryClient(options),store,calls,stored};
}
test('ordinary receiver downloads and decrypts from VC origin even when new sends are disabled',async()=>{
 const {client,calls}=setup();const bundle=await client.bundle(candidate);const document=await client.document(bundle);
 assert.equal(document.subject,'普通邮件 / Résumé 👋');assert.deepEqual(await client.blob(bundle,document.attachments[0].blobId),Uint8Array.from([0,255,128,1]));
 assert.ok(calls.filter(c=>!c.url.endsWith('/service-config')).every(c=>c.headers.authorization||c.headers['DMP-Identity']||Object.keys(c.headers).some(k=>/identity/i.test(k))));
});
test('ordinary origin download rejects another chain locator or tampered receipt before plaintext',async()=>{
 const {client}=setup();await assert.rejects(client.bundle({...candidate,transactionId:'F'.repeat(64)}));
 const bad=setup('recipient',v=>{if(v.receipt)v.receipt.payment={mode:'none',amount:'1'};return v;});await assert.rejects(bad.client.bundle(candidate));
 await assert.rejects(client.bundle({...candidate,endpoint:'https://other.example'}));
});
test('ordinary acceptance is durable before request, survives lost response, and never contains payment bytes',async()=>{
 const {client,store,calls,stored}=setup('sender');await client.connect();
 const task={endpoint:f.endpoint,manifest:f.manifest,chunks:f.chunks,terms:f.terms,status:{messageId:f.manifest.messageId,state:'uploading',revision:1,updatedAt:f.terms.issuedAt}};
 const originalNow=Date.now;Date.now=()=>Date.parse(f.receipt.acceptedAt);
 try{await store.put(task);const status=await client.submit(task);assert.equal(status.state,'queued');assert.equal(stored.get(task.manifest.messageId).status.state,'queued');
 const sent=JSON.parse(calls.find(c=>c.url.endsWith('/submit')).body);assert.deepEqual(Object.keys(sent).sort(),['expectedRevision','termsId','termsSha256']);assert.equal(sent.termsSha256,p.ordinaryTermsHash(f.terms));}finally{Date.now=originalNow;}
});
test('chain inbox persists failed origin downloads, retries after restart, deduplicates, then rescans head',async()=>{
 let checkpoint,offline=true;const done=new Set(),cursors=[];
 const store={load:async()=>structuredClone(checkpoint),save:async c=>{checkpoint=structuredClone(c);},has:async id=>done.has(id),deliver:async c=>{assert.equal(checkpoint.pending[0].messageId,c.messageId);if(offline)throw new Error('offline');done.add(p.ordinaryCandidateId(c));}};
 const row={hash:candidate.transactionId,code:'OK',valid:true,sender:p.addressOf(candidate.serviceId),receiver:p.addressOf(f.manifest.recipientId),tx:{from:p.addressOf(candidate.serviceId),chainId:'beta',itxJson:{type_url:'fg:t:transfer_v2',data:{typeUrl:'vc',value:f.credential}}}};
 const query=async request=>{cursors.push(request.variables.cursor);return{data:{listTransactions:{code:'OK',page:{cursor:'1',next:false},transactions:[row]}}};};
 const input={recipientId:f.manifest.recipientId,chainId:'beta',matches,store,query};
 assert.equal((await p.syncOrdinaryInbox(input)).pending,1);offline=false;assert.equal((await p.syncOrdinaryInbox(input)).delivered,1);assert.equal((await p.syncOrdinaryInbox(input)).delivered,0);assert.deepEqual(cursors,['0','0','0']);
});

test('zero-stake receiving access does not authorize a new ordinary send or start encryption/upload',async()=>{
 const {client,calls,stored}=setup('sender',value=>{if(value.plan)value.available=true;return value;});
 await assert.rejects(client.create({recipientId:f.manifest.recipientId,subject:'blocked',body:'no upload'}),error=>error.problem?.code==='SENDER_GAS_STAKE_REQUIRED');
 assert.equal(stored.size,0);assert.equal(calls.some(c=>c.url.includes('/encryption-keys')||c.url.includes('/messages/')),false);
});
