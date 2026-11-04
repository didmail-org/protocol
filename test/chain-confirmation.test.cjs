const {test}=require('node:test'),assert=require('node:assert/strict'),p=require('../dist/index.cjs');
const base={chainId:'beta',transactionId:'A'.repeat(64),confirmedAt:'2026-10-27T12:00:00.000Z'};
const block=()=>({...base,blockHeight:'123'});
const ledger=()=>({...base,confirmationPolicy:'arcblock-dolt-ledger/1',ledgerBackend:p.DOLT_LEDGER_BACKEND});
test('distinct block and ledger attestations roundtrip without inventing a ledger height',()=>{
 for(const proof of [block(),{...block(),confirmationPolicy:'arcblock-committed'},ledger()]){
  const policy=proof.confirmationPolicy||'arcblock-committed';
  assert.equal(p.validateChainConfirmation(proof),policy);
  assert.equal(p.validateReceiptChainEvidence({payment:proof,index:{...proof,assetId:'zPublicAsset'}},'beta'),policy);
 }
 assert.equal('blockHeight' in ledger(),false);
});
for(const [name,proof] of Object.entries({
 'zero block height':{...block(),blockHeight:'0'},'numeric height':{...block(),blockHeight:1},
 'ledger disguised as block':{...block(),blockHeight:'0',ledgerBackend:p.DOLT_LEDGER_BACKEND},
 'mixed ledger height':{...ledger(),blockHeight:'123'},'ledger missing backend':{...ledger(),ledgerBackend:undefined},
 'unknown backend':{...ledger(),ledgerBackend:'@ocap/statedb-dolt v1.20.3'},'unknown policy':{...ledger(),confirmationPolicy:'anything'},
 'lowercase hash':{...ledger(),transactionId:'a'.repeat(64)},'short hash':{...ledger(),transactionId:'A'},
 'invalid time':{...ledger(),confirmedAt:'yesterday'},'noncanonical time':{...ledger(),confirmedAt:'2026-10-27T12:00:00Z'},
 'unknown member':{...ledger(),finalized:true},'wrong chain type':{...ledger(),chainId:{}},
}))test('rejects '+name,()=>assert.throws(()=>p.validateChainConfirmation(proof)));
test('receipt never mixes confirmation models, networks, or payment/index fields',()=>{
 assert.throws(()=>p.validateReceiptChainEvidence({payment:ledger(),index:{...block(),assetId:'zAsset'}}));
 assert.throws(()=>p.validateReceiptChainEvidence({payment:ledger(),index:{...ledger(),chainId:'main',assetId:'zAsset'}}));
 assert.throws(()=>p.validateReceiptChainEvidence({payment:ledger(),index:{...ledger(),assetId:'zAsset'}},'main'));
 assert.throws(()=>p.validateReceiptChainEvidence({payment:{...ledger(),assetId:'zAsset'},index:ledger()}));
});
const seed=new Uint8Array(32).fill(7),pk=p.b64u(p.signingPublicKey(seed)),serviceId=p.identityId('z'+'A'.repeat(32));
const profile={profile:'arcblock-transfer-v3-mail-nft/1',chainId:'beta',chainEndpoint:'https://chain.test/api/',paymentAssetId:'zToken',paymentAssetDecimals:18,envelopeFactoryId:'zEnvelope',messageFactoryId:'zMail',servicePayeeAddress:serviceId.slice(8),developerPayeeAddress:'0xabc',indexLocatorField:'subject',confirmationPolicy:'arcblock-dolt-ledger/1'};
function client(policy,allowed){let pins=0;const sdk=new p.DmpClient({endpoint:'https://node.test',identityId:serviceId,secretKey:seed,matches:()=>true,store:{put:async()=>{},get:async()=>{},remove:async()=>{}},expectedChain:{chainId:'beta',chainEndpoint:profile.chainEndpoint,paymentAssetId:profile.paymentAssetId,messageFactoryId:profile.messageFactoryId,developerPayeeAddress:profile.developerPayeeAddress,...(allowed===undefined?{}:{confirmationPolicies:allowed})},pinService:async()=>{pins++;},transport:async()=>({status:200,headers:new Headers(),body:p.utf8(p.canonicalize({protocolVersions:[1],serviceId,apiBaseUrl:'https://node.test/v1',signingKey:{serviceId,publicKey:pk,keyId:p.keyIdOf(p.unb64u(pk))},paymentProfile:{...profile,confirmationPolicy:policy}}))})});return{sdk,pins:()=>pins};}
test('discovery requires explicit local opt-in and rejects unknown policies before pinning',async()=>{
 for(const [policy,allowed,accepted] of [['arcblock-dolt-ledger/1',undefined,false],['arcblock-dolt-ledger/1',['arcblock-dolt-ledger/1'],true],['arcblock-committed',undefined,true],['unknown',['unknown'],false]]){
  const {sdk,pins}=client(policy,allowed);if(accepted)await sdk.connect();else await assert.rejects(()=>sdk.connect());assert.equal(pins(),accepted?1:0);
 }
});
