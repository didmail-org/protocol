const {test}=require('node:test'),assert=require('node:assert/strict');
const p=require('../dist/index.cjs'),fixture=require('./fixtures/dolt-ledger.json');
for(const item of fixture.cases)test(`Dolt membership: ${item.name}`,()=>{
  const response=structuredClone(fixture.response);
  if(item.path){let row=response;for(const key of item.path.slice(0,-1))row=row[key];row[item.path.at(-1)]=item.value;}
  if(item.remove){let row=response;for(const key of item.remove.slice(0,-1))row=row[key];delete row[item.remove.at(-1)];}
  let bytes=p.unb64u(fixture.signedTransaction);
  if(item.alterBytes)bytes[bytes.length-1]^=1;
  if(item.emptyBytes)bytes=new Uint8Array();
  const inspect=()=>p.inspectDoltCommittedRecord(response,bytes,fixture.expectedNetwork,fixture.now);
  if(item.state==='invalid')return assert.throws(inspect);
  const result=inspect();
  if(item.state==='pending')return assert.deepEqual(result,{state:'pending'});
  assert.deepEqual(result,{state:item.state,chainId:'beta',transactionId:p.digest(bytes).toUpperCase(),
    recordedAt:response.data.getTx.info.time,backend:p.DOLT_LEDGER_BACKEND,executionCode:response.data.getTx.info.code});
  assert.equal('blockHeight' in result,false);
});
test('Dolt membership rejects hostile prototypes, unsafe configuration and resource exhaustion',()=>{
  const bytes=p.unb64u(fixture.signedTransaction),run=(body,network='beta',now=fixture.now)=>p.inspectDoltCommittedRecord(body,bytes,network,now);
  for(const body of [null,[],Object.create({data:fixture.response.data}),JSON.parse('{"__proto__":{}}'),{padding:'x'.repeat(8*1024*1024)},
      {...fixture.response,data:{...fixture.response.data,getTx:{code:'OK',info:false}}}])assert.throws(()=>run(body));
  for(const network of ['', 'beta ', 'x'.repeat(129)])assert.throws(()=>run(fixture.response,network));
  for(const now of [-1,NaN,Infinity,0.5])assert.throws(()=>run(fixture.response,'beta',now));
  assert.throws(()=>p.inspectDoltCommittedRecord(fixture.response,new Uint8Array(48*1024+1),'beta',fixture.now));
});
