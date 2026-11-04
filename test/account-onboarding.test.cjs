const {test}=require('node:test'),assert=require('node:assert/strict');
const p=require('../dist/index.cjs');
const seed=new Uint8Array(32).fill(17),id='did:abt:z'+'1'.repeat(30),other='did:abt:z'+'2'.repeat(30);
const matches=(pk,did)=>did===id && p.b64u(pk)===p.b64u(p.signingPublicKey(seed));
const password='correct battery staple';
test('capsule recovers the same identity AND random historical encryption keys; authenticated header and password',async()=>{
 const device=new Uint8Array(32).fill(21),record=p.createDeviceKeyRecord(id,seed,device);
 const body=p.accountRecoveryBody(id,seed,[{record,privateKey:p.b64u(device)}],[]);
 const capsule=await p.encryptAccountRecovery(body,password,matches);
 assert.deepEqual(await p.decryptAccountRecovery(capsule,password,id,matches),body);
 await assert.rejects(()=>p.decryptAccountRecovery(capsule,'incorrect battery staple',id,matches));
 await assert.rejects(()=>p.decryptAccountRecovery(capsule,password,other,matches));
 await assert.rejects(()=>p.decryptAccountRecovery({...capsule,nonce:p.b64u(new Uint8Array(12))},password,id,matches));
 await assert.rejects(()=>p.encryptAccountRecovery({...body,keys:[{record,privateKey:p.b64u(seed)}]},password,matches));
 await assert.rejects(()=>p.encryptAccountRecovery({...body,keys:[...body.keys,...body.keys]},password,matches));
 assert.throws(()=>p.validateAccountRecoveryCapsule({...capsule,iterations:600001}));
 assert.throws(()=>p.validateAccountRecoveryCapsule({...capsule,extra:true}));
});
test('capsule validates before invoking costly native KDF, rejects unsafe passwords and excessive archives',async()=>{
 const body=p.accountRecoveryBody(id,seed,[],[]);let calls=0;const kdf=async()=>{calls++;throw Error('should not derive')};
 await assert.rejects(()=>p.encryptAccountRecovery(body,'',matches,kdf));
 await assert.rejects(()=>p.encryptAccountRecovery(body,'long enough\ud800',matches,kdf));
 await assert.rejects(()=>p.encryptAccountRecovery({...body,keys:new Array(65).fill({})},password,matches,kdf));
 assert.equal(calls,0);
});
test('PKCE and mailbox proof bind all identities, origin, operation and intent',()=>{
 const verifier=p.createAccountVerifier();assert.equal(p.unb64u(verifier).length,32);
 const statement={version:1,operation:'link',intentId:p.uuid(),challenge:p.createAccountVerifier(),origin:'https://node.test',serviceId:id,clientId:id,clientPublicKey:p.b64u(p.signingPublicKey(seed)),arcId:id,mailboxId:id,mailboxPublicKey:p.b64u(p.signingPublicKey(seed)),pkceChallenge:p.accountPkceChallenge(verifier),expiresAt:new Date(Date.now()+600000).toISOString(),revision:0,recoveryDigest:null};
 const proof=p.signAccountLink(statement,seed);assert.equal(p.verifyAccountLink(proof,matches),true);
 for(const edit of [{origin:'https://foreign.test'},{arcId:other},{operation:'recover'},{intentId:p.uuid()},{mailboxId:other}])assert.equal(p.verifyAccountLink({...proof,...edit},matches),false);
 assert.throws(()=>p.accountOrigin('http://192.168.1.23:8788'));
 assert.throws(()=>p.accountPkceChallenge('weak'));
});

test('six-character account passwords recover the original mailbox; overlong passwords fail before KDF',async()=>{
 const body=p.accountRecoveryBody(id,seed,[],[]);
 const capsule=await p.encryptAccountRecovery(body,'abc123',matches);
 assert.deepEqual(await p.decryptAccountRecovery(capsule,'abc123',id,matches),body);
 let calls=0;const kdf=async()=>{calls++;throw Error('must not derive')};
 await assert.rejects(()=>p.encryptAccountRecovery(body,'x'.repeat(1025),matches,kdf));assert.equal(calls,0);
});
