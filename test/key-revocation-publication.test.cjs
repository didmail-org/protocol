const {test}=require('node:test'),assert=require('node:assert/strict'),p=require('../dist/index.cjs');
const seed=new Uint8Array(32).fill(7),other=new Uint8Array(32).fill(8),owner=p.identityId('z'+'a'.repeat(32)),peer=p.identityId('z'+'b'.repeat(32));
const matches=(pk,id)=>[[owner,seed],[peer,other]].some(([who,sk])=>who===id&&Buffer.from(pk).equals(Buffer.from(p.signingPublicKey(sk))));
const record=p.createDeviceKeyRecord(owner,seed,new Uint8Array(32).fill(22));
const clone=v=>v===undefined?undefined:JSON.parse(p.canonicalize(v));
function setup(){
 const rows=new Map(),calls=[];let remote,lose=false,offline=false,change;
 const store={get:async(o,id)=>clone(rows.get(o+'/'+id)),remember:async v=>{const key=v.ownerId+'/'+v.keyId,prior=rows.get(key);if(prior&&p.canonicalize(prior)!==p.canonicalize(v))throw Error('Immutable conflict');rows.set(key,clone(v));}};
 const sdk=(revocations=store)=>new p.DmpClient({endpoint:'https://public-fixture.invalid',identityId:owner,secretKey:seed,matches,revocations,pinService:async()=>{},store:{get:async()=>{},put:async()=>{},remove:async()=>{}},transport:async(url,method,headers,body)=>{
  const value=body.length?JSON.parse(p.text(body)):undefined;calls.push({url,method,value,headers});
  const reply=v=>({status:200,headers:new Headers(),body:p.utf8(JSON.stringify(v))});
  if(new URL(url).pathname.endsWith('/encryption-keys'))return reply({records:[{record,revocation:null}]});
  if(offline)throw Error('Offline');
  if(method==='POST'){
   assert.equal(p.canonicalize(rows.get(owner+'/'+record.keyId)),p.canonicalize(value),'durable before network');
   p.validateKeyRevocation(value,matches);remote??=value;assert.deepEqual(remote,value);
   if(lose){lose=false;throw Error('Response lost');}
   return reply({revocation:change?change(value):remote});
  }
  return reply({record,revocation:change?change(remote):remote});
 }});
 return{rows,store,calls,sdk,set lose(v){lose=v;},set offline(v){offline=v;},set change(v){change=v;}};
}
test('durable signed revocation publishes, verifies by ID and keeps exact bytes on fresh-client retries',async()=>{
 const s=setup();s.lose=true;
 await assert.rejects(()=>s.sdk().revokeKey(record,'retired'),/Response lost/);
 const first=clone(s.rows.get(owner+'/'+record.keyId));
 await new Promise(r=>setTimeout(r,3));
 assert.deepEqual(await s.sdk().revokeKey(record,'retired'),first);
 assert.deepEqual(s.calls.filter(c=>c.method==='POST').map(c=>c.value),[first,first]);
 assert.notEqual(s.calls[0].headers['signature-input'],s.calls[1].headers['signature-input']);
 assert.equal(s.rows.size,1);
});
test('offline intent blocks new receiving even when another origin omits the revocation',async()=>{
 const s=setup();s.offline=true;await assert.rejects(()=>s.sdk().revokeKey(record,'compromised'),/Offline/);
 s.offline=false;assert.equal((await s.sdk().checkReceivingKey()).status,'no_active_key');
 await assert.rejects(()=>s.sdk().revokeKey(record,'retired'),/intent mismatch/);
 assert.equal(s.calls.filter(c=>c.method==='POST').length,1);
});
for(const failure of ['missing-store','read','write','missing-readback','wrong-readback'])test(`revocation ${failure} cannot issue HTTP`,async()=>{
 const s=setup();let store=s.store;
 if(failure==='missing-store')store=null;
 if(failure==='read')store={...store,get:async()=>{throw Error('Disk read');}};
 if(failure==='write')store={...store,remember:async()=>{throw Error('Disk write');}};
 if(failure==='missing-readback')store={...store,remember:async()=>{}};
 if(failure==='wrong-readback'){let reads=0;store={...store,get:async()=>++reads===1?undefined:{}};}
 await assert.rejects(()=>s.sdk(store).revokeKey(record,'retired'));
 assert.equal(s.calls.length,0);
});
for(const mutate of [v=>({...v,reason:'invalid'}),v=>({...v,keyId:'bad'}),v=>({...v,ownerId:peer}),v=>({...v,proof:{...v.proof,signature:'A'.repeat(86)}})])test('invalid cached intent fails before HTTP',async()=>{
 const s=setup(),signed=p.signArtifact('DMP1-KEY-REVOCATION',{protocolVersion:1,ownerId:owner,keyId:record.keyId,revokedAt:new Date().toISOString(),reason:'retired'},owner,seed);
 s.rows.set(owner+'/'+record.keyId,mutate(signed));await assert.rejects(()=>s.sdk().revokeKey(record,'retired'));assert.equal(s.calls.length,0);
});
test('rejects foreign, changed signed key and unknown reason without durable write or HTTP',async()=>{
 const s=setup();for(const [key,reason]of [[p.createKeyRecord(peer,other),'retired'],[{...record,expiresAt:'2099-01-01T00:00:00.000Z'},'retired'],[record,'invalid']])await assert.rejects(()=>s.sdk().revokeKey(key,reason));
 assert.equal(s.calls.length,0);assert.equal(s.rows.size,0);
});
for(const altered of [()=>null,()=>false,v=>({...v,reason:'rotated'}),v=>p.signArtifact('DMP1-KEY-REVOCATION',{...p.unsignedArtifact(v),revokedAt:new Date(Date.parse(v.revokedAt)-1).toISOString()},owner,seed)])test('changed or missing acknowledgment never replaces the local immutable intent',async()=>{
 const s=setup();s.change=altered;await assert.rejects(()=>s.sdk().revokeKey(record,'retired'));assert.equal(s.rows.size,1);assert.equal(s.calls.length,1);
});
test('successful POST with omitted GET revocation remains an uncertain publication',async()=>{
 const s=setup();let count=0;s.change=v=>++count===1?v:null;
 await assert.rejects(()=>s.sdk().revokeKey(record,'retired'));assert.equal(s.calls.length,2);assert.equal(s.rows.size,1);
});
test('expired public records can be revoked without an archived private key',async()=>{
 const old=p.createDeviceKeyRecord(owner,seed,new Uint8Array(32).fill(22),new Date('2020-01-01T00:00:00.000Z'));
 const s=setup();s.change=undefined;
 // The actual HTTP registry must return the same historical immutable record.
 const transport=async(url,method,_headers,body)=>({status:200,headers:new Headers(),body:p.utf8(JSON.stringify(method==='POST'?{revocation:JSON.parse(p.text(body))}:{record:old,revocation:clone(s.rows.get(owner+'/'+old.keyId))}))});
 const client=new p.DmpClient({endpoint:'https://public-fixture.invalid',identityId:owner,secretKey:seed,matches,revocations:s.store,pinService:async()=>{},store:{get:async()=>{},put:async()=>{},remove:async()=>{}},transport});
 assert.equal((await client.revokeKey(old,'compromised')).keyId,old.keyId);
});
test('revocation retains historic private bytes and delivered ciphertext remains decryptable',async()=>{
 const secret=new Uint8Array(32).fill(22),before=new Uint8Array(secret),s=setup();
 const sealed=p.sealMessage({senderId:peer,recipientId:owner,serviceId:owner,planId:'public-plan',secretKey:other,senderKey:p.createKeyRecord(peer,other),recipientKey:record,subject:'Historic public fixture',body:'Retained after revocation',matches});
 await s.sdk().revokeKey(record,'compromised');
 const client=new p.DmpClient({endpoint:'https://public-fixture.invalid',identityId:owner,secretKey:seed,matches,revocations:s.store,keys:{records:async()=>[record],secret:async()=>new Uint8Array(secret),save:async()=>{throw Error('No key changes expected');}},pinService:async()=>{},store:{get:async()=>{},put:async()=>{},remove:async()=>{}},transport:async url=>{const parts=new URL(url).pathname.split('/'),blob=parts[5],index=Number(parts[7]);return{status:200,headers:new Headers(),body:p.unb64u(sealed.chunks[blob][index])};}});
 assert.equal((await client.document(sealed.manifest)).body.text,'Retained after revocation');assert.deepEqual(secret,before);
});
