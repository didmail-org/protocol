import { addressOf, b64u, unb64u, randomBytes, digest, utf8, isUuid, canonicalize } from './codec';
import { signArtifact, verifyArtifact, sha256, type IdentityMatcher, type Proof } from './crypto';
import { expectKeys, validTimestamp } from './message';
export const ACCOUNT_LINK_DOMAIN = 'DIDMAIL-ACCOUNT-LINK/1';
export type AccountOperation = 'link' | 'recover' | 'revoke';
export interface AccountLinkStatement {
  version: 1; operation: AccountOperation; intentId: string; challenge: string;
  origin: string; serviceId: string; clientId: string; clientPublicKey: string;
  arcId: string; mailboxId: string; mailboxPublicKey: string;
  pkceChallenge: string; expiresAt: string; revision: number; recoveryDigest: string | null;
}
export type AccountLinkProof = AccountLinkStatement & { proof: Proof };
export function accountOrigin(value: string): string {
  const u = new URL(value);
  if (u.origin !== value || u.username || u.password || !(u.protocol === 'https:' || (u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname.endsWith('.localhost'))))) throw new Error('Fixed HTTPS account origin required');
  return u.origin;
}
export const createAccountVerifier = () => b64u(randomBytes(32));
export const accountPkceChallenge = (verifier: string) => { unb64u(verifier, 32); return b64u(sha256(utf8(verifier))); };
export const accountStatementDigest = (value: AccountLinkStatement) => digest(utf8(canonicalize(value)));
export function validateAccountLinkStatement(value: unknown, matches: IdentityMatcher): asserts value is AccountLinkStatement {
  expectKeys(value, ['version', 'operation', 'intentId', 'challenge', 'origin', 'serviceId', 'clientId', 'clientPublicKey', 'arcId', 'mailboxId', 'mailboxPublicKey', 'pkceChallenge', 'expiresAt', 'revision', 'recoveryDigest']);
  if (value.version !== 1 || !['link', 'recover', 'revoke'].includes(value.operation as string) || !isUuid(value.intentId) || !validTimestamp(value.expiresAt) || !Number.isSafeInteger(value.revision) || (value.revision as number) < 0 || !(value.recoveryDigest === null || (typeof value.recoveryDigest === 'string' && /^[a-f0-9]{64}$/.test(value.recoveryDigest)))) throw new Error('Invalid account statement');
  accountOrigin(value.origin as string); addressOf(value.serviceId as string); addressOf(value.arcId as string); addressOf(value.mailboxId as string); addressOf(value.clientId as string);
  unb64u(value.challenge as string, 32); unb64u(value.pkceChallenge as string, 32);
  if (!matches(unb64u(value.clientPublicKey as string, 32), value.clientId as string) || !matches(unb64u(value.mailboxPublicKey as string, 32), value.mailboxId as string)) throw new Error('Account public key mismatch');
  if (value.operation !== 'recover' && (value.clientId !== value.mailboxId || value.clientPublicKey !== value.mailboxPublicKey)) throw new Error('Link must be signed by the mailbox');
}
export function signAccountLink(statement: AccountLinkStatement, secret: Uint8Array): AccountLinkProof {
  return signArtifact(ACCOUNT_LINK_DOMAIN, statement, statement.clientId, secret);
}
export function verifyAccountLink(value: AccountLinkProof, matches: IdentityMatcher): boolean {
  try { const { proof, ...statement } = value; validateAccountLinkStatement(statement, matches); return verifyArtifact(ACCOUNT_LINK_DOMAIN, value, value.clientId, matches) && proof.publicKey === value.clientPublicKey; } catch { return false; }
}
