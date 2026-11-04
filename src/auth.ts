import { b64, unb64, b64u, unb64u, utf8, digest, unhex, uuid, isUuid, addressOf } from './codec';
import { ed25519, seedOf, signingPublicKey, type IdentityMatcher } from './crypto';
const components = '("@method" "@target-uri" "content-digest" "dmp-identity" "dmp-identity-key")';
const digestHeader = (body: Uint8Array) => `sha-256=:${b64(unhex(digest(body)))}:`;
const base = (method: string, url: string, headers: Record<string,string>, params: string) => [
  `"@method": ${method}`, `"@target-uri": ${url}`, `"content-digest": ${headers['content-digest']}`,
  `"dmp-identity": ${headers['dmp-identity']}`, `"dmp-identity-key": ${headers['dmp-identity-key']}`, `"@signature-params": ${params}`,
].join('\n');
const validateTarget = (method: string, url: string) => {
  if (!['GET','PUT','POST','DELETE'].includes(method)) throw new Error('Unsupported method');
  const u = new URL(url);
  if (u.username || u.password || u.hash || !['http:','https:'].includes(u.protocol) || u.href !== url) throw new Error('Invalid request target');
};
export function signRequest(method: string, url: string, body: Uint8Array, senderId: string, secret: Uint8Array, options: { nowSeconds?:number; nonce?:string } = {}): Record<string,string> {
  validateTarget(method,url); addressOf(senderId);
  const created = options.nowSeconds ?? Math.floor(Date.now()/1000), nonce = options.nonce ?? uuid();
  if (!Number.isSafeInteger(created) || !isUuid(nonce)) throw new Error('Invalid signature parameters');
  const params = `${components};created=${created};expires=${created+60};nonce="${nonce}";keyid="${senderId}#identity";alg="ed25519"`;
  const headers: Record<string,string> = { 'content-digest':digestHeader(body), 'dmp-identity':senderId,'dmp-identity-key':b64u(signingPublicKey(secret)), 'signature-input':`dmp=${params}` };
  headers.signature = `dmp=:${b64(ed25519.sign(utf8(base(method,url,headers,params)),seedOf(secret)))}:`;
  return headers;
}
export function verifyRequest(method:string,url:string,body:Uint8Array,headers:Headers,matches:IdentityMatcher, nowSeconds=Math.floor(Date.now()/1000)): { identityId:string;publicKey:Uint8Array;nonce:string;expires:number } {
  validateTarget(method,url);
  const identity = headers.get('dmp-identity') || ''; addressOf(identity);
  const pk = unb64u(headers.get('dmp-identity-key') || '',32);
  if (!matches(pk,identity) || headers.get('content-digest') !== digestHeader(body)) throw new Error('Request digest or identity mismatch');
  const input = headers.get('signature-input') || '';
  const prefix = 'dmp='+components;
  if (!input.startsWith(prefix)) throw new Error('Invalid covered components');
  const suffix = input.slice(prefix.length);
  const parsed = /^;created=(0|[1-9][0-9]*);expires=(0|[1-9][0-9]*);nonce="([0-9a-f-]+)";keyid="([^"\r\n]+)";alg="ed25519"$/.exec(suffix);
  if (!parsed) throw new Error('Invalid signature input');
  const created=Number(parsed[1]),expires=Number(parsed[2]),nonce=parsed[3];
  if (!Number.isSafeInteger(created)||!Number.isSafeInteger(expires)||!isUuid(nonce)||parsed[4]!==identity+'#identity'||created>nowSeconds+30||expires<created||expires>created+60||nowSeconds>expires+30) throw new Error('Signature expired or invalid');
  const sig = /^dmp=:([A-Za-z0-9+/]+={0,2}):$/.exec(headers.get('signature')||'');
  if (!sig) throw new Error('Invalid signature');
  const signature=unb64(sig[1]);
  const h:Record<string,string> = { 'content-digest':headers.get('content-digest')!, 'dmp-identity':identity,'dmp-identity-key':headers.get('dmp-identity-key')! };
  if(signature.length!==64||!ed25519.verify(signature,utf8(base(method,url,h,input.slice(4))),pk,{zip215:false})) throw new Error('Invalid signature');
  return {identityId:identity,publicKey:pk,nonce,expires};
}
