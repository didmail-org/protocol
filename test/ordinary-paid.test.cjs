const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const p=require('../dist/index.cjs');
const f=JSON.parse(fs.readFileSync(path.join(__dirname,'../docs/protocol/dmp-2/fixtures/ordinary-paid.json'),'utf8'));
const sk=name=>Uint8Array.from(Buffer.from(f.secretKeys[name].replace(/^0x/,''),'hex'));
const keys=new Map(['sender','recipient','service'].map(n=>[f.manifest[n==='service'?'serviceId':n+'Id'],p.signingPublicKey(sk(n))]));
const matches=(pk,id)=>keys.has(id)&&Buffer.from(pk).equals(Buffer.from(keys.get(id)));
const pk=keys.get(f.manifest.senderId),native=id=>p.addressOf(id);
const transaction=()=>({from:native(f.manifest.senderId),pk,chainId:'beta',serviceFee:'0',signatures:[{signer:native(f.manifest.senderId),pk}],itx:{typeUrl:'fg:t:transfer_v3',inputs:[{owner:native(f.manifest.senderId),tokens:[{address:f.terms.settlement.assetId,value:'180'}]}],outputs:[{owner:native(f.manifest.serviceId),tokens:[{address:f.terms.settlement.assetId,value:'180'}]}],data:{typeUrl:'json',value:p.ordinaryPaymentMetadata(f.manifest,f.terms)}}});
test('paid ordinary terms bind integer attachment pricing and 100% origin-node income, with independent payment and notification evidence',()=>{
 p.validateOrdinaryTerms(f.terms,f.manifest,matches,Date.parse(f.receipt.acceptedAt));p.validateOrdinaryReceipt(f.receipt,f.manifest,f.terms,f.credential,matches);
 assert.equal(f.terms.totalAmount,'180');assert.equal(f.terms.settlement.storageAmount,'80');assert.equal(f.receipt.payment.mode,'transfer-v3');
 assert.notEqual(f.receipt.payment.transaction.transactionId,f.receipt.notification.transaction.transactionId);
 assert.equal('index' in f.receipt,false);
 for(const mutate of [v=>v.settlement.storageAmount='81',v=>v.settlement.payeeId=f.manifest.recipientId,v=>v.settlement.decimals=6,v=>v.totalAmount='0180',v=>v.settlement.developerAmount='1']){
  const value=p.unsignedArtifact(structuredClone(f.terms));mutate(value);assert.throws(()=>p.validateOrdinaryTerms(p.signOrdinaryTerms(value,sk('service')),f.manifest,matches,Date.parse(f.receipt.acceptedAt)));
 }
});
test('ordinary payment authorization rejects extra outputs, factories, changed terms, recipient and hidden gas charges',()=>{
 const input={manifest:f.manifest,terms:f.terms,request:f.paymentRequest,publicKey:pk};p.authorizeOrdinaryPayment(transaction(),input);
 for(const mutate of [v=>v.serviceFee='1',v=>v.delegator='attacker',v=>v.itx.outputs.push(v.itx.outputs[0]),v=>v.itx.outputs[0].owner=native(f.manifest.recipientId),v=>v.itx.outputs[0].tokens[0].value='181',v=>v.itx.inputs[0].assets=['nft'],v=>v.itx.data.value.termsSha256='a'.repeat(64),v=>v.itx.typeUrl='fg:t:acquire_asset_v3',v=>v.signatures.push(v.signatures[0])]){const value=transaction();mutate(value);assert.throws(()=>p.authorizeOrdinaryPayment(value,input));}
 assert.throws(()=>p.authorizeOrdinaryPayment(transaction(),{...input,request:{...f.paymentRequest,termsId:f.manifest.messageId}}));
});
