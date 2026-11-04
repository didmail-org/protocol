const {test}=require('node:test');const assert=require('node:assert/strict');const {validateReceiptChainEvidence}=require('../dist/index.cjs');
const {receipt:fixture}=require('./fixtures/node-funded-nft.json');
const index=fixture.index;
test('node-funded receipts require a real positive mint attestation and never invent payer evidence',()=>{
 const value=structuredClone(fixture);assert.equal(validateReceiptChainEvidence(value,'beta'),'arcblock-committed');
 for(const bad of [{...value,payment:{...index}},{...value,funding:{...value.funding,amount:'0'}},{...value,index:{...index,blockHeight:'0'}},{index}])assert.throws(()=>validateReceiptChainEvidence(bad,'beta'));
});
