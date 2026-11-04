const {test}=require('node:test');
const assert=require('node:assert/strict');
const p=require('../dist/index.cjs');
const owner=p.identityId('z'+'a'.repeat(32)),secret=new Uint8Array(32).fill(7),publicKey=p.signingPublicKey(secret);
const matches=(key,id)=>id===owner&&Buffer.from(key).equals(Buffer.from(publicKey));
const now=Date.parse('2026-10-27T00:00:00.000Z');
function record(created,expires){const key=p.createKeyRecord(owner,secret,new Date(created));return expires===undefined?key:p.signArtifact('DMP1-KEY-RECORD',{...p.unsignedArtifact(key),expiresAt:new Date(expires).toISOString()},owner,secret);}
for(const skew of [0,1,1000,30000])test(`key creation ${skew}ms ahead uses the documented bounded clock tolerance`,()=>assert.doesNotThrow(()=>p.validateKeyRecord(record(now+skew),matches,now)));
test('creation beyond 30 seconds remains invalid',()=>assert.throws(()=>p.validateKeyRecord(record(now+30001),matches,now)));
for(const expiry of [now-1,now])test(`expiry ${expiry-now}ms from now is rejected without grace`,()=>assert.throws(()=>p.validateKeyRecord(record(now-1000,expiry),matches,now)));
test('expiry one millisecond later is still valid',()=>assert.doesNotThrow(()=>p.validateKeyRecord(record(now-1000,now+1),matches,now)));
test('future creation cannot be later than its expiry',()=>assert.throws(()=>p.validateKeyRecord(record(now+1000,now+500),matches,now)));
test('lifetime is positive and bounded at 366 days',()=>{
 assert.doesNotThrow(()=>p.validateKeyRecord(record(now,now+366*86400000),matches,now));
 assert.throws(()=>p.validateKeyRecord(record(now,now+366*86400000+1),matches,now));
});
for(const time of [NaN,Infinity,-Infinity])test(`invalid validation clock ${time} fails closed`,()=>assert.throws(()=>p.validateKeyRecord(record(now),matches,time)));
test('clock tolerance does not exempt proof or identity verification',()=>{
 const key=record(now+1000);key.proof.signature='A'.repeat(86);
 assert.throws(()=>p.validateKeyRecord(key,matches,now));
 assert.throws(()=>p.validateKeyRecord(record(now),()=>false,now));
});
