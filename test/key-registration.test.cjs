const {test}=require('node:test');
const assert=require('node:assert/strict');
const p=require('../dist/index.cjs');
const secret=new Uint8Array(32).fill(7),otherSecret=new Uint8Array(32).fill(8);
const owner=p.identityId('z'+'a'.repeat(32)),other=p.identityId('z'+'b'.repeat(32));
const matches=(key,id)=>[[owner,secret],[other,otherSecret]].some(([who,sk])=>id===who&&Buffer.from(key).equals(Buffer.from(p.signingPublicKey(sk))));
const response=(status,value)=>({status,headers:new Headers(),body:p.utf8(JSON.stringify(value))});
function client(transport){return new p.DmpClient({endpoint:'https://public-fixture.invalid',identityId:owner,secretKey:secret,matches,pinService:async()=>{},store:{put:async()=>{},get:async()=>undefined,remove:async()=>{}},transport});}
for(const mode of ['echo','altered-authentic','bad-proof','wrong-owner','missing-record','revoked','false-revocation'])test(`registration response ${mode} must match the submitted signed record`,async()=>{
 let puts=0,candidate;
 const sdk=client(async(_url,method,_headers,body)=>{
  if(method==='GET')return response(404,{status:404,code:'KEY_NOT_FOUND',detail:'Public fixture'});
  puts++;candidate=JSON.parse(p.text(body));let record=structuredClone(candidate);
  if(mode==='altered-authentic')record=p.signArtifact('DMP1-KEY-RECORD',{...p.unsignedArtifact(record),expiresAt:new Date(Date.now()+364*86400000).toISOString()},owner,secret);
  if(mode==='bad-proof')record.proof.signature='A'.repeat(86);
  if(mode==='wrong-owner')record=p.createKeyRecord(other,otherSecret);
  return response(201,mode==='missing-record'?{}:{record,revocation:mode==='revoked'?{revoked:true}:mode==='false-revocation'?false:null});
 });
 if(mode==='echo')assert.deepEqual(await sdk.ownKey(),candidate);else await assert.rejects(()=>sdk.ownKey());
 assert.equal(puts,1);
});
for(const mode of ['valid-old','wrong-owner','wrong-key-id','revoked','false-revocation'])test(`existing key lookup ${mode} never silently re-registers`,async()=>{
 let puts=0;let record=mode==='wrong-owner'?p.createKeyRecord(other,otherSecret):p.createKeyRecord(owner,mode==='wrong-key-id'?otherSecret:secret,new Date(Date.now()-86400000));
 // Authorize both public fixture signing keys for one owner to model a real
 // identity's distinct encryption keys without relaxing lookup-key binding.
 if(mode==='wrong-key-id')record=p.signArtifact('DMP1-KEY-RECORD',p.unsignedArtifact(record),owner,secret);
 const sdk=client(async(_url,method)=>{if(method==='PUT')puts++;return response(200,{record,revocation:mode==='revoked'?{revoked:true}:mode==='false-revocation'?false:null});});
 if(mode==='valid-old')assert.deepEqual(await sdk.ownKey(),record);else await assert.rejects(()=>sdk.ownKey());
 assert.equal(puts,0);
});
for(const revocation of [false,0,'',{}])test(`recipient lookup does not use a key with non-null revocation ${JSON.stringify(revocation)}`,async()=>{
 const record=p.createKeyRecord(other,otherSecret);
 const sdk=client(async()=>response(200,{records:[{record,revocation}]}));
 await assert.rejects(()=>sdk.recipientKey(other),/Recipient must connect/);
});
