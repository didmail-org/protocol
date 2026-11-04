const {test}=require('node:test');
const assert=require('node:assert/strict');
const http=require('node:http');
const zlib=require('node:zlib');
const p=require('../dist/index.cjs');

const empty=new Uint8Array();
const bounded=(value,limit=16,headers={})=>p.readBoundedResponse(new Response(value,{headers}),{maxResponseBytes:limit});
const quick=(promise)=>Promise.race([
  promise,
  new Promise((_,reject)=>{const timer=setTimeout(()=>reject(new Error('Bounded read did not stop')),1500);timer.unref();}),
]);

test('invalid limits reject before network dispatch and zero permits empty bodies',async()=>{
  const original=global.fetch;let calls=0;
  global.fetch=async()=>{calls++;return new Response(null,{status:204});};
  try{
    for(const maxResponseBytes of [-1,1.5,NaN,Infinity,null,'16',p.MAX_RESPONSE_BYTES+1])
      await assert.rejects(()=>p.fetchTransport('https://fixture.invalid','GET',{},empty,{maxResponseBytes}),/Invalid response byte limit/);
    assert.equal(calls,0);
    const response=await p.fetchTransport('https://fixture.invalid','GET',{},empty,{maxResponseBytes:0});
    assert.equal(response.body.length,0);
  }finally{global.fetch=original;}
});

test('a missing streaming API never falls back to unbounded arrayBuffer',async()=>{
  const original=global.fetch;let buffered=0;
  global.fetch=async()=>({status:200,url:'',headers:new Headers(),arrayBuffer:async()=>{buffered++;return new ArrayBuffer(32);}});
  try{
    await assert.rejects(()=>p.fetchTransport('https://fixture.invalid','GET',{},empty),/streaming response or a bounded native transport/);
    assert.equal(buffered,0);
  }finally{global.fetch=original;}
});

test('declared and actual response lengths are bounded, including a lying header',async()=>{
  await assert.rejects(()=>bounded(new Uint8Array(17),16,{'content-length':'17'}),p.ResponseLimitError);
  await assert.rejects(()=>bounded(new Uint8Array(17),16,{'content-length':'1'}),p.ResponseLimitError);
  for(const length of ['-1','1e3','4,4','9007199254740992'])
    await assert.rejects(()=>bounded(new Uint8Array(1),16,{'content-length':length}),/Invalid response content length/);
  assert.equal((await bounded(new Uint8Array(16))).length,16);
  assert.equal((await bounded(null,0,{'content-length':'1024'})).length,0);
});

test('limit failure and abort do not wait for a noncooperative stream cancellation',async()=>{
  let cancelled=0;
  const source=new ReadableStream({
    start(controller){controller.enqueue(new Uint8Array(17));},
    cancel(){cancelled++;return new Promise(()=>{});},
  });
  await assert.rejects(()=>quick(bounded(source)),p.ResponseLimitError);
  assert.equal(cancelled,1);
  const abort=new AbortController();
  const pending=new ReadableStream({cancel(){cancelled++;return new Promise(()=>{});}});
  const reading=p.readBoundedResponse(new Response(pending),{maxResponseBytes:16},abort.signal);
  abort.abort(new Error('Fixture cancellation'));
  await assert.rejects(()=>quick(reading),/Fixture cancellation/);
  assert.equal(cancelled,2);
});

test('stream buffer views are copied before the producer can mutate or retain them',async()=>{
  const backing=new Uint8Array(4096);backing[0]=7;let pulls=0;
  const source=new ReadableStream({pull(controller){
    if(pulls++===0)controller.enqueue(backing.subarray(0,1));
    else{backing.fill(9);controller.close();}
  }},{highWaterMark:0});
  assert.deepEqual(await bounded(source),new Uint8Array([7]));
});

test('fetch cancels an over-limit loopback response before the server ends it',async()=>{
  let requests=0;
  let closed;
  const server=http.createServer((req,res)=>{
    requests++;
    assert.equal(req.headers['x-didmail-max-response-bytes'],undefined);
    closed=new Promise(resolve=>res.once('close',resolve));
    res.writeHead(200,{'content-type':'application/octet-stream'});
    res.flushHeaders();
    res.write(Buffer.alloc(1024));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    await assert.rejects(()=>quick(p.fetchTransport(`http://127.0.0.1:${server.address().port}`,'GET',{},empty,{maxResponseBytes:128})),p.ResponseLimitError);
    assert.equal(requests,1);
    await quick(closed);
  }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});

test('gzip expansion is counted after decoding, while valid compression overhead is allowed',async()=>{
  const server=http.createServer((req,res)=>{
    const bytes=req.url==='/bomb'?Buffer.alloc(64*1024):Buffer.from(Array.from({length:128},(_,i)=>i));
    const compressed=zlib.gzipSync(bytes);
    res.writeHead(200,{'content-encoding':'gzip','content-length':String(compressed.length)});
    res.end(compressed);
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const origin=`http://127.0.0.1:${server.address().port}`;
  try{
    await assert.rejects(()=>p.fetchTransport(origin+'/bomb','GET',{},empty,{maxResponseBytes:128}),p.ResponseLimitError);
    const result=await p.fetchTransport(origin+'/valid','GET',{},empty,{maxResponseBytes:128});
    assert.equal(result.body.length,128);
    assert.deepEqual(result.body,Uint8Array.from({length:128},(_,i)=>i));
  }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});

test('default fetch rejects redirects without a request to the destination',async()=>{
  let captures=0;
  const server=http.createServer((req,res)=>{
    if(req.url==='/capture'){captures++;res.end('{}');return;}
    res.writeHead(307,{location:'/capture'});res.end();
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    await assert.rejects(()=>p.fetchTransport(`http://127.0.0.1:${server.address().port}/redirect`,'POST',{'content-type':'application/json'},p.utf8('{}')));
    assert.equal(captures,0);
  }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
