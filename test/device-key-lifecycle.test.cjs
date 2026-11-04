const {test}=require('node:test');
const assert=require('node:assert/strict');
const p=require('../dist/index.cjs');
const seed=new Uint8Array(32).fill(7),peerSeed=new Uint8Array(32).fill(9);
const owner=p.identityId('z'+'a'.repeat(32)),peer=p.identityId('z'+'b'.repeat(32)),service=p.identityId('z'+'c'.repeat(32));
const matches=(pk,id)=>[[owner,seed],[peer,peerSeed]].some(([who,sk])=>who===id&&Buffer.from(pk).equals(Buffer.from(p.signingPublicKey(sk))));
const response=(status,value)=>({status,headers:new Headers(),body:p.utf8(JSON.stringify(value))});
function archive(){
 const entries=new Map();let writeArgument;
 return {entries,get writeArgument(){return writeArgument;},
  async records(){return [...entries.values()].map(item=>structuredClone(item.record));},
  async secret(id){return entries.has(id)?new Uint8Array(entries.get(id).secret):undefined;},
  async save(record,secret){writeArgument=secret;const old=entries.get(record.keyId);if(old&&(p.canonicalize(old.record)!==p.canonicalize(record)||!Buffer.from(old.secret).equals(Buffer.from(secret))))throw new Error('Immutable archive conflict');entries.set(record.keyId,{record:structuredClone(record),secret:new Uint8Array(secret)});},
 };
}
function setup(keys=archive(),override){
 const remote=new Map(),calls=[];
 const sdk=()=>new p.DmpClient({endpoint:'https://public-fixture.invalid',identityId:owner,secretKey:seed,matches,keys,pinService:async()=>{},store:{put:async()=>{},get:async()=>undefined,remove:async()=>{}},transport:async(url,method,headers,body)=>{
  calls.push({url,method,body:new Uint8Array(body)});
  const id=new URL(url).pathname.split('/').at(-1);
  if(override){const value=await override({id,method,body,remote,keys});if(value)return value;}
  if(method==='GET')return remote.has(id)?response(200,{record:remote.get(id),revocation:null}):response(404,{status:404,detail:'Not found'});
  const record=JSON.parse(p.text(body));assert.deepEqual(keys.entries.get(id).record,record,'publication requires prior durable record');assert.equal(p.keyIdOf(p.encryptionPublicKey(keys.entries.get(id).secret)),id,'publication requires its durable private key');remote.set(id,record);return response(201,{record,revocation:null});
 }});
 return {keys,remote,calls,sdk};
}
test('rotation persists a fresh random key before publication and does not alter caller identity secret',async()=>{
 const s=setup(),before=new Uint8Array(seed),record=await s.sdk().rotateKey();
 assert.notEqual(record.keyId,p.createKeyRecord(owner,seed).keyId);
 assert.equal(s.remote.size,1);assert.equal(s.keys.entries.size,1);assert.deepEqual(seed,before);
 assert.ok(s.keys.writeArgument.every(byte=>byte===0),'temporary private key erased after persistence');
 assert.ok(s.keys.entries.get(record.keyId).secret.some(byte=>byte!==0),'store owns an independent durable copy');
 assert.deepEqual(await s.sdk().ownKey(),record);assert.equal(s.calls.filter(c=>c.method==='PUT').length,1);
 const body=p.text(s.calls.find(c=>c.method==='PUT').body);assert.ok(!body.includes(p.b64u(s.keys.entries.get(record.keyId).secret)),'no private key in registration');
});
for(const failure of ['write-rejected','record-not-persisted','private-key-not-persisted','wrong-private-key'])test(`rotation ${failure} cannot perform any network request`,async()=>{
 const keys=archive();
 if(failure==='write-rejected')keys.save=async()=>{throw new Error('Disk unavailable');};
 if(failure==='record-not-persisted')keys.records=async()=>[];
 if(failure==='private-key-not-persisted')keys.secret=async()=>undefined;
 if(failure==='wrong-private-key')keys.secret=async()=>new Uint8Array(32).fill(1);
 const s=setup(keys);await assert.rejects(()=>s.sdk().rotateKey());assert.equal(s.calls.length,0);
 if(keys.writeArgument)assert.ok(keys.writeArgument.every(x=>x===0));
});
test('lost publication response survives a fresh client without creating another key or registration',async()=>{
 let lose=true;
 const s=setup(archive(),({method,body,remote})=>{if(method==='PUT'&&lose){lose=false;const record=JSON.parse(p.text(body));remote.set(record.keyId,record);throw new Error('Response lost after acceptance');}});
 await assert.rejects(()=>s.sdk().rotateKey(),/Response lost/);assert.equal(s.keys.entries.size,1);
 assert.deepEqual(await s.sdk().ownKey(),[...s.remote.values()][0]);assert.equal(s.keys.entries.size,1);assert.equal(s.calls.filter(c=>c.method==='PUT').length,1);
});
test('unaccepted publication retries the same immutable record after restart',async()=>{
 let fail=true;
 const s=setup(archive(),({method})=>{if(method==='PUT'&&fail){fail=false;throw new Error('Offline before acceptance');}});
 await assert.rejects(()=>s.sdk().rotateKey());const record=(await s.keys.records())[0];assert.equal(s.remote.size,0);
 assert.deepEqual(await s.sdk().ownKey(),record);assert.equal(s.keys.entries.size,1);assert.deepEqual(s.calls.filter(c=>c.method==='PUT').map(c=>p.text(c.body)),[p.canonicalize(record),p.canonicalize(record)]);
});
for(const marker of [false,0,{},''])test(`non-null revocation ${JSON.stringify(marker)} prevents reuse without a replacement`,async()=>{
 const s=setup();const key=await s.sdk().rotateKey();s.calls.length=0;
 const denied=setup(s.keys,()=>response(200,{record:key,revocation:marker}));await assert.rejects(()=>denied.sdk().ownKey(),/revoked/);assert.equal(denied.calls.filter(c=>c.method==='PUT').length,0);assert.equal(s.keys.entries.size,1);
});
test('expired selected key fails closed while its old private key remains in the archive',async()=>{
 const keys=archive(),sk=p.randomBytes(32),old=p.createDeviceKeyRecord(owner,seed,sk,new Date('2020-01-01T00:00:00.000Z'));await keys.save(old,sk);
 const s=setup(keys);await assert.rejects(()=>s.sdk().ownKey(),/expired/);assert.equal(s.calls.length,0);assert.equal(keys.entries.size,1);
});
test('authenticated replacement of an immutable public record is rejected',async()=>{
 const s=setup();const original=await s.sdk().rotateKey();
 s.remote.set(original.keyId,p.signArtifact('DMP1-KEY-RECORD',{...p.unsignedArtifact(original),expiresAt:new Date(Date.parse(original.expiresAt)-1).toISOString()},owner,seed));
 await assert.rejects(()=>s.sdk().ownKey(),/lookup identity mismatch/);assert.equal(s.keys.entries.size,1);
});
test('old and new random-key messages decrypt after rotation, and missing/wrong keys fail authentication',async()=>{
 const s=setup(),first=await s.sdk().rotateKey();
 const seal=record=>p.sealMessage({senderId:peer,recipientId:owner,serviceId:service,planId:'public-plan',secretKey:peerSeed,senderKey:p.createKeyRecord(peer,peerSeed),recipientKey:record,subject:'历史 / device key',body:'Public fixture only',matches});
 const old=seal(first);await new Promise(resolve=>setTimeout(resolve,2));const second=await s.sdk().rotateKey(),fresh=seal(second);
 assert.notEqual(first.keyId,second.keyId);assert.equal(s.keys.entries.size,2);
 for(const sealed of [old,fresh]){
  const blob=sealed.manifest.documentBlobId,envelope=sealed.manifest.keyEnvelopes.find(k=>k.ownerId===owner),sk=await s.keys.secret(envelope.keyId),before=new Uint8Array(sk);
  assert.equal(p.decodeDocument(p.decryptBlob(sealed.manifest,blob,sealed.chunks[blob].map(value=>p.unb64u(value)),owner,seed,matches,undefined,sk)).body.text,'Public fixture only');
  assert.deepEqual(sk,before,'low-level API preserves caller-owned archived key');
  assert.throws(()=>p.decryptBlob(sealed.manifest,blob,sealed.chunks[blob].map(value=>p.unb64u(value)),owner,seed,matches),/Historic private key/);
  assert.throws(()=>p.decryptBlob(sealed.manifest,blob,sealed.chunks[blob].map(value=>p.unb64u(value)),owner,seed,matches,undefined,new Uint8Array(32)),/Historic private key/);
 }
 // Exercise the actual SDK archive resolver and public ciphertext transport.
 const sdk=new p.DmpClient({endpoint:'https://public-fixture.invalid',identityId:owner,secretKey:seed,matches,keys:s.keys,pinService:async()=>{},store:{put:async()=>{},get:async()=>undefined,remove:async()=>{}},transport:async(url)=>{const segments=new URL(url).pathname.split('/'),id=segments[3],sealed=id===old.manifest.messageId?old:fresh,blob=segments[5],index=Number(segments[7]);return {status:200,headers:new Headers(),body:p.unb64u(sealed.chunks[blob][index])};}});
 assert.equal((await sdk.document(old.manifest)).subject,'历史 / device key');assert.equal((await sdk.document(fresh.manifest)).body.text,'Public fixture only');
});
test('same-time device records use the service keyId ascending tie-break',async()=>{
 const s=setup(),at=new Date();
 const records=[];
 for(const value of [21,22]){
  const secret=new Uint8Array(32).fill(value),record=p.createDeviceKeyRecord(owner,seed,secret,at);
  await s.keys.save(record,secret);s.remote.set(record.keyId,record);records.push(record);
 }
 records.sort((a,b)=>a.keyId.localeCompare(b.keyId));
 assert.deepEqual(await s.sdk().ownKey(),records[0]);assert.equal(s.calls.filter(c=>c.method==='PUT').length,0);
});
function receivingSetup(){
 const keys=archive(),remote=new Map();let puts=0;
 let advertised=[];
 const sdk=new p.DmpClient({endpoint:'https://public-fixture.invalid',identityId:owner,secretKey:seed,matches,keys,pinService:async()=>{},store:{put:async()=>{},get:async()=>undefined,remove:async()=>{}},transport:async(url,method,_headers,body)=>{
  if(new URL(url).pathname.endsWith('/encryption-keys'))return response(200,{records:advertised.map(record=>({record,revocation:null}))});
  const id=new URL(url).pathname.split('/').at(-1);
  if(method==='GET')return remote.has(id)?response(200,{record:remote.get(id),revocation:null}):response(404,{status:404,detail:'Missing'});
  puts++;const record=JSON.parse(p.text(body));remote.set(id,record);advertised.push(record);return response(201,{record,revocation:null});
 }});
 return{keys,sdk,get puts(){return puts;},set records(value){advertised=value;}};
}
test('receiving readiness cannot replace another device primary with a new recovery key',async()=>{
 const s=receivingSetup(),oldSecret=new Uint8Array(32).fill(21),newSecret=new Uint8Array(32).fill(22);
 const old=p.createDeviceKeyRecord(owner,seed,oldSecret,new Date(Date.now()-86400000)),current=p.createDeviceKeyRecord(owner,seed,newSecret);
 await s.keys.save(old,oldSecret);s.records=[old,current];
 await assert.rejects(()=>s.sdk.ensureReceivingKey(),/requires import/);assert.equal(s.puts,0);assert.equal(s.keys.entries.size,1);
 await s.keys.save(current,newSecret);assert.deepEqual(await s.sdk.ensureReceivingKey(),current);assert.equal(s.puts,0);
});
test('a fresh device with no archive cannot implicitly replace an advertised random primary',async()=>{
 const s=receivingSetup();s.records=[p.createDeviceKeyRecord(owner,seed,new Uint8Array(32).fill(22))];
 await assert.rejects(()=>s.sdk.ensureReceivingKey(),/requires import/);assert.equal(s.puts,0);assert.equal(s.keys.entries.size,0);
});
test('empty registry bootstrap registers one recovery key then verifies its advertisement',async()=>{
 const s=receivingSetup();const key=await s.sdk.ensureReceivingKey();assert.equal(key.keyId,p.createKeyRecord(owner,seed).keyId);assert.equal(s.puts,1);
 assert.deepEqual(await s.sdk.ensureReceivingKey(),key);assert.equal(s.puts,1);
});
test('nonempty expired registry requires explicit setup without silently creating a recovery primary',async()=>{
 const s=receivingSetup();s.records=[p.createDeviceKeyRecord(owner,seed,new Uint8Array(32).fill(22),new Date('2020-01-01T00:00:00.000Z'))];
 await assert.rejects(()=>s.sdk.ensureReceivingKey(),/setup required/);assert.equal(s.puts,0);
});
test('registry primary selection sorts authenticated records rather than trusting response order',async()=>{
 const s=receivingSetup(),old=p.createKeyRecord(owner,seed,new Date(Date.now()-86400000)),current=p.createDeviceKeyRecord(owner,seed,new Uint8Array(32).fill(22));
 s.records=[old,current];assert.deepEqual(await s.sdk.recipientKey(owner),current);assert.equal(s.puts,0);
});
test('malformed or oversized registry cannot cause bootstrap publication',async()=>{
 const s=receivingSetup();s.records=Array.from({length:33},()=>p.createKeyRecord(owner,seed));
 await assert.rejects(()=>s.sdk.ensureReceivingKey(),/Invalid encryption key registry/);assert.equal(s.puts,0);
});

test('explicit receiving check never bootstraps an empty registry',async()=>{
 const s=receivingSetup();assert.deepEqual(await s.sdk.checkReceivingKey(),{status:'unregistered'});
 assert.equal(s.puts,0);assert.equal(s.keys.entries.size,0);
});
test('explicit receiving check distinguishes missing private key and current local readiness',async()=>{
 const s=receivingSetup(),secret=new Uint8Array(32).fill(22),record=p.createDeviceKeyRecord(owner,seed,secret);s.records=[record];
 assert.deepEqual(await s.sdk.checkReceivingKey(),{status:'import_required',record});assert.equal(s.puts,0);
 await s.keys.save(record,secret);assert.deepEqual(await s.sdk.checkReceivingKey(),{status:'ready',record});assert.equal(s.puts,0);
});
test('explicit receiving check distinguishes expired registry and recovery readiness without writes',async()=>{
 const s=receivingSetup();s.records=[p.createDeviceKeyRecord(owner,seed,new Uint8Array(32).fill(22),new Date('2020-01-01T00:00:00.000Z'))];
 assert.deepEqual(await s.sdk.checkReceivingKey(),{status:'no_active_key'});assert.equal(s.puts,0);
 const record=p.createKeyRecord(owner,seed);s.records=[record];assert.deepEqual(await s.sdk.checkReceivingKey(),{status:'ready',record});assert.equal(s.puts,0);
});
function indexedArchive(){
 const keys=archive();let returned;
 keys.lookup=async id=>{const item=keys.entries.get(id);if(!item)return undefined;returned={record:structuredClone(item.record),secret:new Uint8Array(item.secret)};return returned;};
 keys.records=async()=>{throw new Error('Unexpected full archive scan');};
 keys.secret=async()=>{throw new Error('Unexpected second private-key read');};
 return{keys,get returned(){return returned;}};
}
test('indexed rotation verifies a durable pair without enumeration and erases the returned secret',async()=>{
 const indexed=indexedArchive(),s=setup(indexed.keys);const record=await s.sdk().rotateKey();
 assert.equal(s.remote.size,1);assert.equal(indexed.returned.record.keyId,record.keyId);assert(indexed.returned.secret.every(value=>value===0));
});
test('indexed receiving lookup avoids enumeration and erases caller-owned bytes',async()=>{
 const s=receivingSetup(),indexed=indexedArchive(),secret=new Uint8Array(32).fill(22),record=p.createDeviceKeyRecord(owner,seed,secret);
 await s.keys.save(record,secret);s.records=[record];
 let returned; s.keys.lookup=async id=>{returned=await indexed.keys.lookup(id);return returned;};
 await indexed.keys.save(record,secret);s.keys.records=indexed.keys.records;s.keys.secret=indexed.keys.secret;
 assert.deepEqual(await s.sdk.checkReceivingKey(),{status:'ready',record});assert(returned.secret.every(value=>value===0));assert.equal(s.puts,0);
});
for(const mode of ['absent','changed-record','wrong-private','lookup-failed'])test(`indexed ${mode} never falls back to scanning or publication`,async()=>{
 const s=receivingSetup(),secret=new Uint8Array(32).fill(22),record=p.createDeviceKeyRecord(owner,seed,secret);s.records=[record];let returned,scans=0;
 s.keys.records=async()=>{scans++;throw new Error('Unexpected full archive scan');};
 s.keys.lookup=async()=>{
  if(mode==='lookup-failed')throw new Error('Storage unavailable');if(mode==='absent')return undefined;
  returned={record:mode==='changed-record'?{...record,expiresAt:new Date(Date.parse(record.expiresAt)-1).toISOString()}:record,secret:mode==='wrong-private'?new Uint8Array(32):new Uint8Array(secret)};return returned;
 };
 if(mode==='absent')assert.deepEqual(await s.sdk.checkReceivingKey(),{status:'import_required',record});else await assert.rejects(()=>s.sdk.checkReceivingKey());
 if(returned)assert(returned.secret.every(value=>value===0));assert.equal(scans,0);assert.equal(s.puts,0);
});
test('historic document lookup uses one authenticated indexed pair and erases it after decryption',async()=>{
 const indexed=indexedArchive(),s=setup(indexed.keys),record=await s.sdk().rotateKey();
 const sealed=p.sealMessage({senderId:peer,recipientId:owner,serviceId:service,planId:'public-plan',secretKey:peerSeed,senderKey:p.createKeyRecord(peer,peerSeed),recipientKey:record,subject:'Indexed history',body:'Public fixture only',matches});
 const sdk=new p.DmpClient({endpoint:'https://public-fixture.invalid',identityId:owner,secretKey:seed,matches,keys:indexed.keys,pinService:async()=>{},store:{put:async()=>{},get:async()=>undefined,remove:async()=>{}},transport:async(url)=>{const parts=new URL(url).pathname.split('/');return{status:200,headers:new Headers(),body:p.unb64u(sealed.chunks[parts[5]][Number(parts[7])])};}});
 assert.equal((await sdk.document(sealed.manifest)).subject,'Indexed history');assert(indexed.returned.secret.every(value=>value===0));
});

for(const mode of ['absent','changed-record','wrong-private','lookup-failed'])test(`indexed rotation ${mode} prevents every publication request`,async()=>{
 const indexed=indexedArchive(),base=indexed.keys.lookup,s=setup(indexed.keys);let returned;
 indexed.keys.lookup=async id=>{
  if(mode==='absent')return undefined;if(mode==='lookup-failed')throw new Error('Storage unavailable');
  returned=await base(id);
  if(mode==='changed-record')returned.record={...returned.record,expiresAt:new Date(Date.parse(returned.record.expiresAt)-1).toISOString()};
  if(mode==='wrong-private')returned.secret.fill(0);
  return returned;
 };
 await assert.rejects(()=>s.sdk().rotateKey());assert.equal(s.calls.length,0);
 if(returned)assert(returned.secret.every(value=>value===0));assert(indexed.keys.writeArgument.every(value=>value===0));
});
test('explicit publication retries the selected key after loss even with a newer local key',async()=>{
 const indexed=indexedArchive();let lose=true;
 const s=setup(indexed.keys,({method,body,id,remote})=>{if(method==='PUT'&&lose){lose=false;remote.set(id,JSON.parse(p.text(body)));throw new Error('Response lost');}});
 await assert.rejects(()=>s.sdk().rotateKey(),/Response lost/);const first=[...indexed.keys.entries.values()][0].record;
 await new Promise(resolve=>setTimeout(resolve,2));const extraSecret=new Uint8Array(32).fill(28),extra=p.createDeviceKeyRecord(owner,seed,extraSecret);await indexed.keys.save(extra,extraSecret);
 s.calls.length=0;assert.deepEqual(await s.sdk().publishKey(first.keyId),first);
 assert.equal(indexed.keys.entries.size,2);assert.equal(s.remote.size,1);assert(s.calls.every(call=>call.url.endsWith(first.keyId)));assert(indexed.returned.secret.every(value=>value===0));
});
test('explicit legacy-store publication does not select a newer archived key',async()=>{
 const s=setup(),first=await s.sdk().rotateKey(),other=new Uint8Array(32).fill(23);await s.keys.save(p.createDeviceKeyRecord(owner,seed,other),other);
 s.calls.length=0;assert.deepEqual(await s.sdk().publishKey(first.keyId),first);assert(s.calls.every(call=>call.url.endsWith(first.keyId)));
});
for(const mode of ['missing','wrong-private','expired','wrong-id','invalid-id'])test(`explicit publication ${mode} cannot issue HTTP`,async()=>{
 const indexed=indexedArchive(),s=setup(indexed.keys),secret=new Uint8Array(32).fill(22),record=p.createDeviceKeyRecord(owner,seed,secret,mode==='expired'?new Date('2020-01-01T00:00:00.000Z'):new Date());
 if(mode!=='missing')await indexed.keys.save(record,secret);
 const lookup=indexed.keys.lookup;indexed.keys.lookup=async id=>{const pair=await lookup(id);if(pair&&mode==='wrong-private')pair.secret.fill(0);if(pair&&mode==='wrong-id')pair.record.keyId='0'.repeat(64);return pair;};
 await assert.rejects(()=>s.sdk().publishKey(mode==='invalid-id'?'../other':record.keyId));assert.equal(s.calls.length,0);if(indexed.returned)assert(indexed.returned.secret.every(value=>value===0));
});
