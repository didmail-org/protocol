import { canonicalize, digest } from './codec';

export const DOLT_LEDGER_BACKEND = '@ocap/statedb-dolt v1.20.2';
export const DOLT_COMMITTED_RECORD_QUERY = 'query DoltCommittedRecord($hash:String!){getChainInfo{code info{network consensusVersion synced}} getTx(hash:$hash){code info{hash height code time tx{chainId}}}}';
export type DoltCommittedRecord =
  | { state: 'pending' }
  | { state: 'committed'|'rejected'; chainId: string; transactionId: string; recordedAt: string; backend: typeof DOLT_LEDGER_BACKEND; executionCode: string };

/**
 * Inspect a primary StateDB record returned by the locally configured trusted RPC.
 * This is NOT a signature verifier, block proof, or complete settlement policy.
 * Callers must first authenticate/authorize the exact original signed bytes and
 * bind the transport to their configured endpoint; service-supplied RPCs are unsafe.
 * Dolt's placeholder height/synced fields never establish confirmation here.
 */
export function inspectDoltCommittedRecord(
  response: unknown,
  originalSignedBytes: Uint8Array,
  expectedNetwork: string,
  now = Date.now(),
): DoltCommittedRecord {
  const fail = (): never => { throw new Error('Invalid Dolt ledger confirmation evidence'); };
  if (!(originalSignedBytes instanceof Uint8Array) || originalSignedBytes.length === 0 || originalSignedBytes.length > 48*1024 ||
      typeof expectedNetwork !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(expectedNetwork) ||
      !Number.isSafeInteger(now) || now < 0) return fail();
  // Canonicalization rejects hostile prototypes/members, deep nesting and invalid
  // scalar values before we read any evidence; responses also have a size budget.
  if (canonicalize(response).length > 8*1024*1024) return fail();
  const body = response as any;
  if (!body || typeof body !== 'object' || Array.isArray(body) ||
      (body.errors !== undefined && (!Array.isArray(body.errors) || body.errors.length !== 0))) return fail();
  const chain = body.data?.getChainInfo;
  if (chain?.code !== 'OK' || chain.info?.network !== expectedNetwork || chain.info?.synced !== true ||
      chain.info?.consensusVersion !== DOLT_LEDGER_BACKEND) return fail();
  const result = body.data?.getTx;
  if (result?.code !== 'OK') return fail();
  if (result.info === null) return {state:'pending'};
  const info = result.info;
  const transactionId = digest(originalSignedBytes).toUpperCase();
  if (!info || info.hash !== transactionId || info.height !== '0' ||
      info.tx?.chainId !== expectedNetwork || typeof info.code !== 'string' ||
      !/^[A-Z][A-Z0-9_]{0,63}$/.test(info.code) || typeof info.time !== 'string') return fail();
  const at = Date.parse(info.time);
  if (!Number.isSafeInteger(at) || at < 0 || at > now+30000 || new Date(at).toISOString() !== info.time) return fail();
  return {state:info.code==='OK'?'committed':'rejected',chainId:expectedNetwork,
    transactionId,recordedAt:info.time,backend:DOLT_LEDGER_BACKEND,executionCode:info.code};
}
