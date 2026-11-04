import { addressOf,unb64u,canonicalize,utf8,text,amount,randomBytes,digest } from './codec';
import { signRequest } from './auth';
import { createKeyRecord,createDeviceKeyRecord,validateKeyRecord,validateKeyRevocation,validateManifest,manifestHash,decodeDocument,decryptBlob,sealMessage,chunkSize,type PlainAttachment } from './message';
import { signArtifact,verifyArtifact,keyIdOf,encryptionPublicKey,recoveryEncryptionSecret,type IdentityMatcher } from './crypto';
import { confirmationPolicy,validateReceiptChainEvidence } from './chain-confirmation';
import { validateServerReceipt, validateServerQuote } from './server-mail';
import type { Discovery,KeyRecord,KeyRevocation,Quote,PaymentRequest,DeliveryStatus,Receipt,Manifest,SealedMessage,EmailDocument,Problem } from './types';
import { fetchTransport, responseByteLimit, type Transport, type TransportOptions } from './transport';
export { fetchTransport, responseByteLimit, readBoundedResponse, ResponseLimitError, DEFAULT_MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES, type Transport, type TransportOptions } from './transport';
export class DmpError extends Error { constructor(public readonly problem:Problem) {super(problem.detail);this.name='DmpError';} }
export interface DmpTask extends SealedMessage { endpoint:string; quote?:Quote; paymentRequest?:PaymentRequest; signedTransaction?:string; status?:DeliveryStatus; submissionAuthorized?:boolean }
export interface TaskStore { put(task:DmpTask):Promise<void>; get(messageId:string):Promise<DmpTask|undefined>; remove(messageId:string):Promise<void> }
export interface RevocationStore {
  get(ownerId:string,keyId:string):Promise<KeyRevocation|undefined>;
  // Atomically preserve the first canonical fact; reject conflicting replacements.
  remember(revocation:KeyRevocation):Promise<void>;
}
export interface ArchivedEncryptionKey { record:KeyRecord;secret:Uint8Array }
export interface EncryptionKeyStore {
  /** Optional indexed, authenticated pair lookup. Return a fresh caller-owned
   * secret; absence is authoritative. Errors must not trigger a full scan. */
  lookup?(keyId:string):Promise<ArchivedEncryptionKey|undefined>;
  /** All immutable signed public records, including expired/revoked history. */
  records():Promise<KeyRecord[]>;
  /** Return a fresh, caller-owned copy. Callers erase it after use. */
  secret(keyId:string):Promise<Uint8Array|undefined>;
  /** Atomically persist copies of record AND secret; reject immutable conflicts.
   * The caller retains ownership of both arguments and erases the secret. */
  save(record:KeyRecord,secret:Uint8Array):Promise<void>;
}
export interface ClientOptions { endpoint:string;identityId:string;secretKey:Uint8Array;matches:IdentityMatcher;store:TaskStore;transport?:Transport;revocations?:RevocationStore;keys?:EncryptionKeyStore;expectedChain?:{chainId:string;chainEndpoint:string;paymentAssetId:string;messageFactoryId:string;developerPayeeAddress:string;confirmationPolicies?:readonly import('./types').ConfirmationPolicy[]};pinService:(serviceId:string,publicKey:string)=>Promise<void> }
export type ReceivingKeyStatus = {status:'ready'|'import_required';record:KeyRecord}|{status:'unregistered'|'no_active_key'};
export type Progress=(stage:string,completed?:number,total?:number)=>void;
export class DmpClient {
  readonly endpoint:string; private discovery?:Discovery;
  private readonly seenRevocations=new Map<string,string>();
  constructor(private readonly options:ClientOptions){
    const u=new URL(options.endpoint);
    if(u.username||u.password||u.search||u.hash||u.pathname.replace(/\/+$/,'')||!(u.protocol==='https:'||(u.protocol==='http:'&&(u.hostname==='localhost'||u.hostname.endsWith('.localhost')||u.hostname==='127.0.0.1'||u.hostname==='[::1]'))))throw new Error('An HTTPS origin is required (HTTP only for loopback development)');
    this.endpoint=u.origin;addressOf(options.identityId);
  }
  private async request(path:string,method='GET',value?:unknown,binary=false,publicRead=false,options?:TransportOptions){
    const url=this.endpoint+path,body=binary?value as Uint8Array:value===undefined?new Uint8Array():utf8(canonicalize(value));
    const headers:Record<string,string>={accept:binary?'application/octet-stream':'application/json'};
    if(method!=='GET')headers['content-type']=binary?'application/octet-stream':'application/json';
    if(!publicRead)Object.assign(headers,signRequest(method,url,body,this.options.identityId,this.options.secretKey));
    const maxResponseBytes=responseByteLimit(options);
    const response=await(this.options.transport||fetchTransport)(url,method,headers,body,{maxResponseBytes});
    if(response.body.length>maxResponseBytes)throw new Error('DMP response exceeds byte limit');
    if(response.status>=300&&response.status<400)throw new Error('DMP service redirects are not allowed');
    if(response.status>=400){let problem:Problem;try{problem=JSON.parse(text(response.body));}catch{problem={type:'about:blank',status:response.status,title:'Request failed',code:'SERVICE_UNAVAILABLE',detail:'Service request failed',requestId:response.headers.get('x-request-id')||'',recoveryAction:'query_status'};}throw new DmpError(problem);}
    return response;
  }
  private async json<T>(path:string,method='GET',value?:unknown,publicRead=false):Promise<T>{const r=await this.request(path,method,value,false,publicRead);return JSON.parse(text(r.body)) as T;}
  async connect():Promise<Discovery>{
    const d=await this.json<Discovery>('/.well-known/didmail','GET',undefined,true),expected=this.options.expectedChain;
    if(!d.protocolVersions?.includes(1)||d.apiBaseUrl!==this.endpoint+'/v1'||d.signingKey?.serviceId!==d.serviceId||keyIdOf(unb64u(d.signingKey.publicKey,32))!==d.signingKey.keyId||!this.options.matches(unb64u(d.signingKey.publicKey,32),d.serviceId))throw new Error('Invalid DMP discovery or service identity');
    if(expected&&(d.paymentProfile.chainId!==expected.chainId||d.paymentProfile.chainEndpoint.replace(/\/+$/,'')!==expected.chainEndpoint.replace(/\/+$/,'')||d.paymentProfile.paymentAssetId!==expected.paymentAssetId||(!d.features?.includes('server-mail')&&(d.paymentProfile.messageFactoryId!==expected.messageFactoryId||d.paymentProfile.developerPayeeAddress.toLowerCase()!==expected.developerPayeeAddress.toLowerCase()))))throw new Error('Service settlement profile differs from this client');
    const policy=confirmationPolicy(d.paymentProfile.confirmationPolicy);
    if(expected&&!(expected.confirmationPolicies??['arcblock-committed']).includes(policy))throw new Error('Service confirmation policy differs from this client');
    await this.options.pinService(d.serviceId,d.signingKey.publicKey);this.discovery=d;return d;
  }
  private async keyWasRevoked(ownerId:string,keyId:string):Promise<boolean>{
    const key=ownerId+'/'+keyId,encoded=this.seenRevocations.get(key);
    const record:KeyRevocation|undefined=encoded?JSON.parse(encoded):await this.options.revocations?.get(ownerId,keyId);
    if(record===undefined)return false;validateKeyRevocation(record,this.options.matches);
    if(record.ownerId!==ownerId||record.keyId!==keyId)throw new Error('Cached key revocation binding mismatch');
    this.seenRevocations.set(key,canonicalize(record));return true;
  }
  private async observeRevocation(value:unknown,ownerId:string,keyId?:string):Promise<void>{
    const record=value as KeyRevocation;
    try{validateKeyRevocation(record,this.options.matches);if(record.ownerId!==ownerId||(keyId!==undefined&&record.keyId!==keyId))return;}catch{return;}
    const key=record.ownerId+'/'+record.keyId,encoded=canonicalize(record),prior=this.seenRevocations.get(key);
    if(prior&&prior!==encoded)throw new Error('Conflicting immutable key revocation');
    this.seenRevocations.set(key,encoded);
    await this.options.revocations?.remember(JSON.parse(encoded));
  }
  private async archivedSecret(record:KeyRecord):Promise<Uint8Array>{
    const secret=await this.options.keys?.secret(record.keyId);
    if(!secret)throw new Error('Historic private key required');
    try{if(record.ownerId!==this.options.identityId||secret.length!==32||keyIdOf(encryptionPublicKey(secret))!==record.keyId)throw new Error('Invalid archived encryption key');return secret;}
    catch(error){secret.fill(0);throw error;}
  }
  private async archivedSecretIfPresent(record:KeyRecord,mismatch:string):Promise<Uint8Array|undefined>{
    const keys=this.options.keys;
    if(keys?.lookup){
      const pair=await keys.lookup(record.keyId);
      if(!pair)return undefined;
      const secret=pair.secret;
      try{
        if(canonicalize(pair.record)!==canonicalize(record))throw new Error(mismatch);
        if(record.ownerId!==this.options.identityId||secret.length!==32||keyIdOf(encryptionPublicKey(secret))!==record.keyId)throw new Error('Invalid archived encryption key');
        return secret;
      }catch(error){secret.fill(0);throw error;}
    }
    const records=await keys?.records(),archived=records?.find(item=>item.keyId===record.keyId);
    if(!archived)return undefined;
    if(canonicalize(archived)!==canonicalize(record))throw new Error(mismatch);
    return this.archivedSecret(archived);
  }
  /** Explicit rotation never deletes old keys or implicitly revokes them. */
  async rotateKey():Promise<KeyRecord>{
    const store=this.options.keys;if(!store)throw new Error('Persistent encryption key store required');
    const secret=randomBytes(32);
    try{
      const record=createDeviceKeyRecord(this.options.identityId,this.options.secretKey,secret);
      validateKeyRecord(record,this.options.matches);
      await store.save(JSON.parse(canonicalize(record)),secret);
      // Read back the durable pair before any public registration request.
      const persisted=await this.archivedSecretIfPresent(record,'Encryption key was not persisted');
      if(!persisted)throw new Error('Encryption key was not persisted');
      persisted.fill(0);
      return await this.publishOwnKey(record,true);
    }finally{secret.fill(0);}
  }
  /** Explicit irreversible local revocation, then idempotent publication.
   * Retains private keys. Local denial survives an offline/uncertain response. */
  async revokeKey(input:KeyRecord,reason:KeyRevocation['reason']):Promise<KeyRevocation>{
    const record:KeyRecord=JSON.parse(canonicalize(input));
    validateKeyRecord(record,this.options.matches,Date.parse(record.createdAt));
    if(record.ownerId!==this.options.identityId||!['rotated','compromised','retired'].includes(reason))throw new Error('Invalid own-key revocation');
    const store=this.options.revocations;if(!store)throw new Error('Persistent revocation store required');
    const owner=record.ownerId,id=record.keyId;
    const validate=(value:KeyRevocation)=>{
      validateKeyRevocation(value,this.options.matches);
      if(value.ownerId!==owner||value.keyId!==id||value.reason!==reason)throw new Error('Revocation intent mismatch');
      return canonicalize(value);
    };
    const cached=await store.get(owner,id);
    const intent:KeyRevocation=cached===undefined
      ?signArtifact('DMP1-KEY-REVOCATION',{protocolVersion:1 as const,ownerId:owner,keyId:id,revokedAt:new Date().toISOString(),reason},owner,this.options.secretKey)
      :JSON.parse(canonicalize(cached));
    const encoded=validate(intent),prior=this.seenRevocations.get(owner+'/'+id);
    if(prior&&prior!==encoded)throw new Error('Conflicting immutable key revocation');
    await store.remember(JSON.parse(encoded));
    const persisted=await store.get(owner,id);
    if(persisted===undefined||validate(persisted)!==encoded)throw new Error('Key revocation was not persisted');
    this.seenRevocations.set(owner+'/'+id,encoded);
    const path=`/v1/identities/${encodeURIComponent(owner)}/encryption-keys/${id}`;
    const result=await this.json<{revocation:KeyRevocation}>(path+'/revocations','POST',JSON.parse(encoded));
    if(validate(result.revocation)!==encoded)throw new Error('Revocation response changed immutable intent');
    const observed=await this.json<{record:KeyRecord;revocation:KeyRevocation}>(path,'GET',undefined,true);
    validateKeyRecord(observed.record,this.options.matches,Date.parse(record.createdAt));
    if(canonicalize(observed.record)!==canonicalize(record)||validate(observed.revocation)!==encoded)throw new Error('Revocation lookup mismatch');
    return JSON.parse(encoded);
  }
  /** Retry one explicitly selected durable key; never generates a replacement. */
  async publishKey(keyId:string):Promise<KeyRecord>{
    if(typeof keyId!=='string'||!/^[0-9a-f]{64}$/.test(keyId))throw new Error('Invalid encryption key ID');
    const store=this.options.keys;if(!store)throw new Error('Persistent encryption key store required');
    let record:KeyRecord;
    if(store.lookup){
      const pair=await store.lookup(keyId);if(!pair)throw new Error('Historic private key required');
      try{
        record=JSON.parse(canonicalize(pair.record));validateKeyRecord(record,this.options.matches);
        if(record.ownerId!==this.options.identityId||record.keyId!==keyId||pair.secret.length!==32||keyIdOf(encryptionPublicKey(pair.secret))!==keyId)throw new Error('Invalid archived encryption key');
      }finally{pair.secret.fill(0);}
    }else{
      const matches=(await store.records()).filter(item=>item.keyId===keyId);
      if(matches.length!==1)throw new Error('Historic private key required');
      record=JSON.parse(canonicalize(matches[0]));validateKeyRecord(record,this.options.matches);
      const secret=await this.archivedSecret(record);secret.fill(0);
    }
    return this.publishOwnKey(record,true);
  }
  async ownKey():Promise<KeyRecord>{
    const records=await this.options.keys?.records();
    if(records?.length){
      // Never fall back to an old/recovery key when the selected device key has
      // expired, was revoked, or cannot be loaded. Rotation must be explicit.
      const ordered=[...records].sort((a,b)=>b.createdAt.localeCompare(a.createdAt)||a.keyId.localeCompare(b.keyId));
      for(const record of ordered){validateKeyRecord(record,this.options.matches,Date.parse(record.createdAt));if(record.ownerId!==this.options.identityId)throw new Error('Encryption key archive identity mismatch');}
      const record=ordered[0];validateKeyRecord(record,this.options.matches);
      const secret=await this.archivedSecret(record);secret.fill(0);
      return this.publishOwnKey(record,true);
    }
    return this.publishOwnKey(createKeyRecord(this.options.identityId,this.options.secretKey),false);
  }
  private async publishOwnKey(candidate:KeyRecord,exact:boolean):Promise<KeyRecord>{
    const path=`/v1/identities/${encodeURIComponent(this.options.identityId)}/encryption-keys/${candidate.keyId}`;
    if(await this.keyWasRevoked(this.options.identityId,candidate.keyId))throw new Error('Encryption recovery key revoked; rotate device key');
    try {const {record,revocation}=await this.json<{record:KeyRecord;revocation:unknown}>(path,'GET',undefined,true);if(revocation!=null){await this.observeRevocation(revocation,this.options.identityId,candidate.keyId);throw new Error('Encryption recovery key revoked; rotate device key');}validateKeyRecord(record,this.options.matches);if(record.ownerId!==this.options.identityId||record.keyId!==candidate.keyId||(exact&&canonicalize(record)!==canonicalize(candidate)))throw new Error('Encryption key lookup identity mismatch');if(await this.keyWasRevoked(record.ownerId,record.keyId))throw new Error('Encryption recovery key revoked; rotate device key');return record;}
    catch(error){if(!(error instanceof DmpError)||error.problem.status!==404)throw error;}
    if(await this.keyWasRevoked(this.options.identityId,candidate.keyId))throw new Error('Encryption recovery key revoked; rotate device key');
    const {record,revocation}=await this.json<{record:KeyRecord;revocation:unknown}>(path,'PUT',candidate);
    if(revocation!=null){await this.observeRevocation(revocation,this.options.identityId,candidate.keyId);throw new Error('Encryption recovery key revoked; rotate device key');}
    validateKeyRecord(record,this.options.matches);if(canonicalize(record)!==canonicalize(candidate))throw new Error('Registration changed the immutable encryption key record');if(await this.keyWasRevoked(record.ownerId,record.keyId))throw new Error('Encryption recovery key revoked; rotate device key');return record;
  }
  private async registryKeys(ownerId:string):Promise<{count:number;active:KeyRecord[]}>{
    const result=await this.json<{records:{record:KeyRecord;revocation:unknown}[]}>(`/v1/identities/${encodeURIComponent(ownerId)}/encryption-keys`,'GET',undefined,true);
    if(!Array.isArray(result.records)||result.records.length>32)throw new Error('Invalid encryption key registry');
    const blocked=new Set<string>(),active:KeyRecord[]=[];
    for(const item of result.records){if(item.revocation!=null){if(typeof item.record?.keyId==='string')blocked.add(item.record.keyId);await this.observeRevocation(item.revocation,ownerId);}}
    for(const item of result.records){
      if(item.revocation!=null||blocked.has(item.record?.keyId))continue;
      try{validateKeyRecord(item.record,this.options.matches);}catch{continue;}
      if(item.record.ownerId===ownerId&&!await this.keyWasRevoked(ownerId,item.record.keyId))active.push(item.record);
    }
    active.sort((a,b)=>b.createdAt.localeCompare(a.createdAt)||a.keyId.localeCompare(b.keyId));
    return{count:result.records.length,active};
  }
  async recipientKey(recipientId:string):Promise<KeyRecord>{
    const result=await this.registryKeys(recipientId);
    if(result.active.length)return result.active[0];
    throw new DmpError({type:'about:blank',status:409,title:'Recipient setup required',code:'RECIPIENT_KEY_UNAVAILABLE',detail:'Recipient must connect to this service and register an encryption key before receiving mail.',requestId:'',recoveryAction:'ask_recipient_to_connect'});
  }
  /** Checks the selected registry without publishing any key. Verified
   * revocation facts may still be persisted locally. */
  async checkReceivingKey():Promise<ReceivingKeyStatus>{
    const registry=await this.registryKeys(this.options.identityId);
    if(registry.count===0)return{status:'unregistered'};
    const current=registry.active[0];
    if(!current)return{status:'no_active_key'};
    const secret=await this.archivedSecretIfPresent(current,'Receiving key record mismatch');
    if(secret){secret.fill(0);return{status:'ready',record:current};}
    const recovery=recoveryEncryptionSecret(this.options.secretKey);
    try{if(keyIdOf(encryptionPublicKey(recovery))===current.keyId)return{status:'ready',record:current};}
    finally{recovery.fill(0);}
    return{status:'import_required',record:current};
  }
  /** Verify the advertised primary key is decryptable here; a stale local key
   * must never silently replace another device's key during inbox setup/send. */
  async ensureReceivingKey():Promise<KeyRecord>{
    let result=await this.checkReceivingKey();
    if(result.status==='unregistered'){await this.ownKey();result=await this.checkReceivingKey();}
    if(result.status==='ready')return result.record;
    if(result.status==='import_required')throw new Error('Current receiving private key requires import');
    throw new Error('Receiving key setup required');
  }
  async create(input:{recipientId:string;subject:string;body:string;mediaType?:'text/plain'|'text/html';planId?:string;attachments?:PlainAttachment[]},progress?:Progress):Promise<DmpTask>{
    const discovery=this.discovery||await this.connect();if(!input.planId&&!discovery.defaultPlan&&!discovery.features?.includes('server-mail'))throw new Error('No paid Envelope NFT plan available');
    const senderKey=await this.ensureReceivingKey(),recipientKey=input.recipientId===this.options.identityId?senderKey:await this.recipientKey(input.recipientId);
    progress?.('encrypting');
    const sealed=sealMessage({...input,senderId:this.options.identityId,serviceId:discovery.serviceId,planId:input.planId||discovery.defaultPlan?.planId||'auto',...(discovery.features?.includes('server-mail')?{automaticDelivery:true as const}:{}),secretKey:this.options.secretKey,senderKey,recipientKey,matches:this.options.matches});
    const task:DmpTask={...sealed,endpoint:this.endpoint};await this.options.store.put(task);return task;
  }
  validateQuote(quote:Quote,manifest:Manifest):void{
    const d=this.discovery;if(!d)throw new Error('Connect before validating quote');
    if(quote.delivery==='server'){validateServerQuote(quote,manifest,this.options.matches);return;}
    const expected=this.options.expectedChain;
    if(expected&&(quote.settlement.messageFactoryId!==expected.messageFactoryId||quote.settlement.developerPayeeAddress.toLowerCase()!==expected.developerPayeeAddress.toLowerCase()))throw new Error('External settlement profile differs from this client');
    if(quote.settlement?.profile==='none')throw new Error('Missing server delivery discriminator');
    confirmationPolicy(quote.settlement?.confirmationPolicy);
    if(!verifyArtifact('DMP1-QUOTE',quote,manifest.serviceId,this.options.matches)||quote.serviceId!==d.serviceId||quote.messageId!==manifest.messageId||quote.manifestSha256!==manifestHash(manifest)||quote.planId!==manifest.planId||Date.parse(quote.expiresAt)<=Date.now()||quote.settlement.payerId!==(quote.funding?manifest.serviceId:this.options.identityId)||quote.settlement.profile!=='arcblock-transfer-v3-mail-nft/1')throw new Error('Invalid or expired quote');
    for(const key of ['chainId','chainEndpoint','paymentAssetId','paymentAssetDecimals','envelopeFactoryId','messageFactoryId','servicePayeeAddress','developerPayeeAddress','indexLocatorField','confirmationPolicy'] as const)if(quote.settlement[key]!==d.paymentProfile[key])throw new Error('Quote settlement snapshot mismatch');
    if(quote.paymentAsset.chainId!==quote.settlement.chainId||quote.paymentAsset.assetId!==quote.settlement.paymentAssetId||quote.paymentAsset.decimals!==18||amount(quote.envelopeAmount)+amount(quote.storageAmount)!==amount(quote.totalAmount)||(quote.funding?0n:amount(quote.indexAmount))+amount(quote.developerAmount)+amount(quote.serviceAmount)!==amount(quote.totalAmount))throw new Error('Invalid quote amount');
    if(quote.funding&&(quote.funding.mode!=='node-sponsored'||quote.funding.sponsorId!==manifest.serviceId||quote.funding.amount!==quote.indexAmount||amount(quote.indexAmount)<=0n||amount(quote.totalAmount)!==0n))throw new Error('Invalid node funding');
  }
  async prepare(task:DmpTask,progress?:Progress):Promise<PaymentRequest>{
    await this.connect();if(task.endpoint!==this.endpoint||task.manifest.senderId!==this.options.identityId)throw new Error('Task owner/service mismatch');
    const id=task.manifest.messageId;
    const session=await this.json<{quote:Quote;missingChunks:{blobId:string;index:number}[]}>(`/v1/messages/${id}`,'PUT',task.manifest);
    this.validateQuote(session.quote,task.manifest);task.quote=session.quote;await this.options.store.put(task);
    const missing=[...session.missingChunks],total=missing.reduce((n,c)=>n+unb64u(task.chunks[c.blobId][c.index]).length,0);let completed=0;
    const upload=async()=>{while(missing.length){const chunk=missing.shift()!;const bytes=unb64u(task.chunks[chunk.blobId][chunk.index]);await this.request(`/v1/messages/${id}/blobs/${chunk.blobId}/chunks/${chunk.index}`,'PUT',bytes,true);completed+=bytes.length;progress?.('uploading',completed,total);}};
    await Promise.all(Array.from({length:Math.min(3,Math.max(1,missing.length))},upload));
    const prepared=await this.json<{quote:Quote;paymentRequest:PaymentRequest}>(`/v1/messages/${id}/prepare`,'POST',{quoteId:task.quote.quoteId});
    this.validateQuote(prepared.quote,task.manifest);task.quote=prepared.quote;task.paymentRequest=prepared.paymentRequest;await this.options.store.put(task);progress?.('awaiting_signature');return prepared.paymentRequest;
  }
  async submit(task:DmpTask,signedTransaction:string):Promise<DeliveryStatus>{
    if(!task.quote||!task.paymentRequest)throw new Error('Task is not prepared');
    if(task.signedTransaction && task.signedTransaction!==signedTransaction)throw new DmpError({type:'about:blank',status:409,title:'Payment conflict',code:'PAYMENT_CONFLICT',detail:'This task already contains a different signed payment. Query its original status.',requestId:'',recoveryAction:'query_status'});
    const local=task.quote.delivery==='server';
    if(local&&(signedTransaction||task.paymentRequest.mode!=='server'))throw new Error('Server delivery must not include a payment');
    if(!local&&task.paymentRequest.mode==='server')throw new Error('Unexpected server delivery');
    const sponsored=task.quote.funding?.mode==='node-sponsored';
    if(sponsored&&(signedTransaction||task.paymentRequest.mode!=='node-sponsored'))throw new Error('Sponsored delivery must not include a sender payment');
    if(!sponsored&&task.paymentRequest.mode==='node-sponsored')throw new Error('Unexpected node funding');
    if(local||sponsored)task.submissionAuthorized=true;else task.signedTransaction=signedTransaction;await this.options.store.put(task);
    try{const status=await this.json<DeliveryStatus>(`/v1/messages/${task.manifest.messageId}/submit`,'POST',{quoteId:task.quote.quoteId,...(local?{delivery:'server'}:sponsored?{fundingMode:'node-sponsored'}:{signedTransaction})});task.status=status;await this.options.store.put(task);return status;}
    catch(error){
      if(error instanceof DmpError && error.problem.status<500)throw error;
      // A network failure after acceptance must be resolved against the SAME task.
      try{const status=await this.status(task.manifest.messageId);if(!['uploading','awaiting_signature'].includes(status.state)){task.status=status;await this.options.store.put(task);return status;}}catch{/* preserve signed task for explicit resume */}
      throw error;
    }
  }
  async status(id:string):Promise<DeliveryStatus>{return this.json(`/v1/messages/${id}/status`);}
  async manifest(id:string):Promise<{manifest:Manifest;receipt?:Receipt}>{return this.json(`/v1/messages/${id}`);}
  async list(mailbox:'inbox'|'outbox',cursor='',limit=50,delivery?:'server'):Promise<{items:{manifest:Manifest;status:DeliveryStatus;receipt?:Receipt}[];nextCursor:string|null}>{return this.json(`/v1/messages?mailbox=${mailbox}&cursor=${encodeURIComponent(cursor)}&limit=${limit}${delivery?'&delivery=server':''}`);}
  async blob(manifest:Manifest,blobId:string,acceptedAt?:string):Promise<Uint8Array>{
    // Authenticate and bound descriptors before using their IDs/counts for I/O.
    validateManifest(manifest,this.options.matches,Date.parse(acceptedAt||manifest.createdAt));
    const descriptor=manifest.blobs.find(b=>b.blobId===blobId);if(!descriptor)throw new Error('Blob missing');const chunks:Uint8Array[]=[];
    if(!manifest.keyEnvelopes.some(key=>key.ownerId===this.options.identityId))throw new Error('Missing ciphertext or key');
    for(let index=0;index<descriptor.chunkCount;index++){
      const bytes=(await this.request(`/v1/messages/${manifest.messageId}/blobs/${blobId}/chunks/${index}`,'GET',undefined,false,false,{maxResponseBytes:chunkSize(descriptor,index)})).body;
      if(bytes.length!==chunkSize(descriptor,index)||digest(bytes)!==descriptor.chunkSha256[index])throw new Error('Ciphertext integrity failure');
      chunks.push(bytes);
    }
    const envelope=manifest.keyEnvelopes.find(key=>key.ownerId===this.options.identityId);
    let secret:Uint8Array|undefined;
    try{
      if(this.options.keys&&envelope){
        secret=await this.archivedSecretIfPresent(envelope.keyRecord,'Historic encryption key record mismatch');
      }
      return decryptBlob(manifest,blobId,chunks,this.options.identityId,this.options.secretKey,this.options.matches,acceptedAt,secret);
    }finally{secret?.fill(0);}
  }
  validateReceipt(manifest:Manifest,receipt:Receipt):void{
    if(receipt&&(receipt.protocolVersion!==1||receipt.serviceId!==manifest.serviceId||!verifyArtifact('DMP1-RECEIPT',receipt,manifest.serviceId,this.options.matches)||receipt.manifestSha256!==manifestHash(manifest)||receipt.messageId!==manifest.messageId||receipt.senderId!==manifest.senderId||receipt.recipientId!==manifest.recipientId))throw new Error('Invalid delivery receipt');
    if(receipt?.funding && receipt.funding.sponsorId!==manifest.serviceId)throw new Error('Invalid receipt sponsor');
    if(receipt?.delivery==='server')validateServerReceipt(receipt,manifest,this.options.matches);
    else if(receipt)validateReceiptChainEvidence(receipt,this.options.expectedChain?.chainId);
    validateManifest(manifest,this.options.matches,Date.parse(receipt.acceptedAt));
  }
  async document(manifest:Manifest,receipt?:Receipt):Promise<EmailDocument>{
    if(receipt)this.validateReceipt(manifest,receipt);
    validateManifest(manifest,this.options.matches,Date.parse(receipt?.acceptedAt||manifest.createdAt));
    const document=decodeDocument(await this.blob(manifest,manifest.documentBlobId,receipt?.acceptedAt));
    const ids=new Set<string>();
    for(const a of document.attachments){
      const blob=manifest.blobs.find(b=>b.blobId===a.blobId);
      if(!blob||a.blobId===manifest.documentBlobId||ids.has(a.blobId)||typeof a.fileName!=='string'||typeof a.mediaType!=='string'||a.sizeBytes!==blob.sizeBytes-16*blob.chunkCount)throw new Error('Invalid attachment descriptor');
      ids.add(a.blobId);
    }
    if(ids.size!==manifest.blobs.length-1)throw new Error('Missing attachment metadata');
    return document;
  }
}
