const {test}=require('node:test'),assert=require('node:assert/strict'),p=require('../dist/index.cjs');
const owner=p.identityId('z'+'a'.repeat(32)),peer=p.identityId('z'+'b'.repeat(32));
const seeds=[7,8].map(n=>new Uint8Array(32).fill(n));
const matches=(pk,id)=>[owner,peer].some((who,i)=>id===who&&Buffer.from(pk).equals(Buffer.from(p.signingPublicKey(seeds[i]))));
const record=p.createKeyRecord(peer,seeds[1]);
const revoke=(key=record,who=peer,sk=seeds[1])=>p.signArtifact('DMP1-KEY-REVOCATION',{protocolVersion:1,ownerId:who,keyId:key.keyId,revokedAt:new Date().toISOString(),reason:'retired'},who,sk);
function memory(){const rows=new Map();return{rows,get:async(o,k)=>rows.get(o+'/'+k),remember:async v=>{rows.set(v.ownerId+'/'+v.keyId,v);}};}
function client(transport,revocations){return new p.DmpClient({endpoint:'https://public-fixture.invalid',identityId:owner,secretKey:seeds[0],matches,revocations,pinService:async()=>{},store:{get:async()=>{},put:async()=>{},remove:async()=>{}},transport:async(...args)=>({status:200,headers:new Headers(),body:p.utf8(JSON.stringify(await transport(...args)))})});}
for(const durable of [false,true])test(`seen signed revocation survives omission, new instance=${durable}`,async()=>{
 const store=durable?memory():undefined;let response={records:[{record,revocation:revoke()}]};let sdk=client(async()=>response,store);
 await assert.rejects(()=>sdk.recipientKey(peer));response={records:[{record,revocation:null}]};if(durable)sdk=client(async()=>response,store);
 await assert.rejects(()=>sdk.recipientKey(peer));if(store)assert.equal(store.rows.size,1);
});
test('scans revocations before selecting a duplicated active record',async()=>{
 const sdk=client(async()=>({records:[{record,revocation:null},{record,revocation:revoke()}]}),memory());await assert.rejects(()=>sdk.recipientKey(peer));
});
test('does not turn unsigned or foreign-owner markers into permanent denials',async()=>{
 const store=memory();for(const invalid of [false,{},revoke(record,owner,seeds[0]),{...revoke(),unexpected:true}]){
  const sdk=client(async()=>({records:[{record,revocation:invalid}]}),store);await assert.rejects(()=>sdk.recipientKey(peer));
 }assert.equal(store.rows.size,0);assert.equal((await client(async()=>({records:[{record,revocation:null}]}),store).recipientKey(peer)).keyId,record.keyId);
});
test('cache read and write failures cannot fall back to a stale active key',async()=>{
 await assert.rejects(()=>client(async()=>({records:[{record,revocation:null}]}),{get:async()=>{throw Error('disk read failed')},remember:async()=>{}}).recipientKey(peer),/disk read failed/);
 await assert.rejects(()=>client(async()=>({records:[{record,revocation:revoke()}]}),{get:async()=>{},remember:async()=>{throw Error('disk write failed')}}).recipientKey(peer),/disk write failed/);
});
test('cached own-key revocation prevents a 404 rollback and re-registration',async()=>{
 const own=p.createKeyRecord(owner,seeds[0]),store=memory();await store.remember(revoke(own,owner,seeds[0]));let requests=0;
 const sdk=client(async()=>{requests++;return{}},store);await assert.rejects(()=>sdk.ownKey(),/revoked/);assert.equal(requests,0);
});
test('invalid cached signatures and mismatched binding fail closed',async()=>{
 for(const bad of [{...revoke(),proof:{...revoke().proof,signature:'A'.repeat(86)}},revoke(p.createKeyRecord(owner,seeds[0]),owner,seeds[0])])await assert.rejects(()=>client(async()=>({records:[{record,revocation:null}]}),{get:async()=>bad,remember:async()=>{}}).recipientKey(peer));
});
for(const mutate of [v=>({...v,protocolVersion:2}),v=>({...v,revokedAt:'invalid'}),v=>({...v,revokedAt:new Date(Date.now()+60000).toISOString()}),v=>({...v,reason:'other'}),v=>({...v,keyId:'bad'})])test('malformed revocation is rejected by the shared validator',()=>assert.throws(()=>p.validateKeyRevocation(mutate(revoke()),matches)));

for(const bad of [null,false,0])test(`corrupted cached primitive ${JSON.stringify(bad)} cannot mean no revocation`,async()=>{await assert.rejects(()=>client(async()=>({records:[{record,revocation:null}]}),{get:async()=>bad,remember:async()=>{}}).recipientKey(peer));});
