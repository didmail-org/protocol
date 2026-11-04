import { accountOrigin, accountPkceChallenge, createAccountVerifier, signAccountLink, validateAccountLinkStatement, type AccountLinkStatement, type AccountOperation } from './account-link';
import { validateAccountRecoveryCapsule, type AccountRecoveryCapsule } from './account-recovery';
import { addressOf, digest, b64u, unb64u, uuid, utf8, text, canonicalize } from './codec';
import { signingPublicKey, type IdentityMatcher } from './crypto';
import { signRequest } from './auth';
import { fetchTransport, type Transport } from './client';
export interface PendingAccountIntent {
  version: 1; endpoint: string; clientId: string; serviceId: string; authorizationOrigin: string;
  intentId: string; operation: AccountOperation; verifier: string;
  response?: {intentId:string;authorizationUrl:string;expiresAt:string;displayCode:string};
  completion?: {verifier:string;proof:ReturnType<typeof signAccountLink>|null;capsule:AccountRecoveryCapsule|null};
}
/** Store MUST encrypt at rest. Save is durable/atomic; never include this object in logs or URLs. */
export interface AccountIntentStore { load(): Promise<PendingAccountIntent|undefined>; save(intent:PendingAccountIntent):Promise<void>; remove():Promise<void> }
export interface AccountCompletion {mailboxId:string;revision:number;revoked:boolean;capsule:AccountRecoveryCapsule|null}
export class AccountLinkClient {
  readonly endpoint: string;
  constructor(private readonly options:{endpoint:string;clientId:string;secretKey:Uint8Array;matches:IdentityMatcher;store:AccountIntentStore;transport?:Transport}) {
    this.endpoint=accountOrigin(options.endpoint);addressOf(options.clientId);
    if(!options.matches(signingPublicKey(options.secretKey),options.clientId))throw new Error('Account client identity mismatch');
  }
  private async request(path:string,body?:unknown) {
    const bytes=body===undefined?new Uint8Array():utf8(canonicalize(body)), method=body===undefined?'GET':'POST', url=this.endpoint+path;
    const headers:Record<string,string>={accept:'application/json'};
    if(body!==undefined)Object.assign(headers,{'content-type':'application/json'},signRequest(method,url,bytes,this.options.clientId,this.options.secretKey));
    const r=await(this.options.transport||fetchTransport)(url,method,headers,bytes,{maxResponseBytes:140000});
    if(r.status>=300&&r.status<400)throw new Error('Account service redirects are not allowed');
    if(r.body.length>140000)throw new Error('Account response too large');
    const result=JSON.parse(text(r.body));
    if(r.status>=400)throw Object.assign(new Error(result.code||'Account request failed'),{code:result.code,status:r.status});
    return result;
  }
  private async pending() {
    const intent=await this.options.store.load();
    if(!intent || intent.version!==1 || intent.endpoint!==this.endpoint || intent.clientId!==this.options.clientId)throw new Error('No matching durable account intent');
    return intent;
  }
  /** Reuses an interrupted intent. Caller opens authorizationUrl only after this returns. */
  async start(operation:AccountOperation):Promise<NonNullable<PendingAccountIntent['response']>> {
    let intent=await this.options.store.load();
    if(intent){await this.pending();if(intent.operation!==operation)throw new Error('Finish or cancel the pending account operation first');}
    else {
      const capabilities=await this.request('/v1/account-links/capabilities');
      if(capabilities.version!==1 || capabilities.enabled!==true)throw new Error('ARC mailbox onboarding is unavailable on this node');
      const authorizationOrigin=accountOrigin(capabilities.authorizationOrigin), discovery=await this.request('/.well-known/didmail');
      if(!discovery.signingKey || discovery.signingKey.serviceId!==discovery.serviceId || !this.options.matches(unb64u(discovery.signingKey.publicKey,32),discovery.serviceId))throw new Error('Invalid node identity');
      intent={version:1,endpoint:this.endpoint,clientId:this.options.clientId,serviceId:discovery.serviceId,authorizationOrigin,intentId:uuid(),operation,verifier:createAccountVerifier()};
      await this.options.store.save(intent);
    }
    const response=await this.request('/v1/account-links/intents',{intentId:intent.intentId,operation:intent.operation,pkceChallenge:accountPkceChallenge(intent.verifier)});
    if(response.intentId!==intent.intentId || response.authorizationUrl!==intent.authorizationOrigin+'/account/authorize?id='+intent.intentId || typeof response.displayCode!=='string' || !/^[A-Za-z0-9_-]{8}$/.test(response.displayCode) || !Number.isFinite(Date.parse(response.expiresAt)) || Date.parse(response.expiresAt)<=Date.now() || Date.parse(response.expiresAt)>Date.now()+630000)throw new Error('Invalid authorization response');
    intent.response=response;await this.options.store.save(intent);return response;
  }
  async approved():Promise<AccountLinkStatement|undefined> {
    const intent=await this.pending(), response=await this.request('/v1/account-links/intents/'+intent.intentId+'/status',{verifier:intent.verifier});
    if(response.status==='pending')return undefined;
    if(response.status!=='approved')throw new Error('Invalid authorization status');
    const statement=response.statement as AccountLinkStatement;validateAccountLinkStatement(statement,this.options.matches);
    if(statement.intentId!==intent.intentId || statement.operation!==intent.operation || statement.origin!==intent.authorizationOrigin || statement.serviceId!==intent.serviceId || statement.clientId!==this.options.clientId || statement.clientPublicKey!==b64u(signingPublicKey(this.options.secretKey)) || statement.pkceChallenge!==accountPkceChallenge(intent.verifier) || Date.parse(statement.expiresAt)<=Date.now() || statement.expiresAt!==intent.response?.expiresAt || statement.challenge.slice(0,8)!==intent.response?.displayCode)throw new Error('Authorization differs from local intent');
    return statement;
  }
  /** Persist completion before sending. A fresh HTTP nonce is generated on each retry. */
  async complete(capsule:AccountRecoveryCapsule|null=null):Promise<AccountCompletion> {
    const intent=await this.pending();
    if(!intent.completion){
      const statement=await this.approved();if(!statement)throw new Error('Approve in ARC first');
      if(capsule){validateAccountRecoveryCapsule(capsule);if(intent.operation!=='link' || capsule.mailboxId!==statement.mailboxId)throw new Error('Recovery capsule mailbox mismatch');}
      intent.completion={verifier:intent.verifier,proof:intent.operation==='recover'?null:signAccountLink(statement,this.options.secretKey),capsule};
      await this.options.store.save(intent);
    } else if(capsule && canonicalize(capsule)!==canonicalize(intent.completion.capsule))throw new Error('Do not change a pending completion');
    const response=await this.request('/v1/account-links/intents/'+intent.intentId+'/complete',intent.completion) as AccountCompletion;
    addressOf(response.mailboxId);
    if(!Number.isSafeInteger(response.revision)||response.revision<1||typeof response.revoked!=='boolean')throw new Error('Invalid binding result');
    const statement=await this.approved();
    if(!statement || response.mailboxId!==statement.mailboxId || response.revision!==statement.revision+(intent.operation==='recover'?0:1))throw new Error('Binding result mailbox mismatch');
    if(intent.operation==='recover'){validateAccountRecoveryCapsule(response.capsule);if(response.capsule!.mailboxId!==response.mailboxId || digest(utf8(canonicalize(response.capsule)))!==statement.recoveryDigest)throw new Error('Recovery response mailbox mismatch');}
    else if(response.capsule!==null || response.revoked!==(intent.operation==='revoke'))throw new Error('Invalid operation result');
    return response;
  }
  /** Call only after the local account/archive commit succeeds, or explicit cancellation. */
  async clearPending():Promise<void>{await this.options.store.remove();}
}
