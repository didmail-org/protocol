import { canonicalize } from './codec';
import { DOLT_LEDGER_BACKEND } from './ledger-confirmation';
import type { ChainConfirmation,ConfirmationPolicy,Receipt } from './types';

export function confirmationPolicy(value:unknown):ConfirmationPolicy {
  if(value==='arcblock-committed'||value==='arcblock-dolt-ledger/1')return value;
  throw new Error('Unsupported chain confirmation policy');
}

/** Validate the service attestation shape; this is not independent RPC evidence. */
export function validateChainConfirmation(value:unknown,index=false):ConfirmationPolicy {
  const fail=():never=>{throw new Error('Invalid chain confirmation attestation');};
  if(!value||typeof value!=='object'||canonicalize(value).length>4096)return fail();
  const row=value as ChainConfirmation&{assetId?:string};
  const policy=confirmationPolicy(row.confirmationPolicy===undefined?'arcblock-committed':row.confirmationPolicy);
  const keys=['chainId','transactionId','confirmedAt',...(index?['assetId']:[])];
  if(policy==='arcblock-dolt-ledger/1')keys.push('confirmationPolicy','ledgerBackend');
  else {keys.push('blockHeight');if(row.confirmationPolicy!==undefined)keys.push('confirmationPolicy');}
  if(Object.keys(row).length!==keys.length||!Object.keys(row).every(k=>keys.includes(k))||
    typeof row.chainId!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(row.chainId)||
    typeof row.transactionId!=='string'||!/^[0-9A-F]{64}$/.test(row.transactionId)||
    typeof row.confirmedAt!=='string'||!Number.isFinite(Date.parse(row.confirmedAt))||new Date(row.confirmedAt).toISOString()!==row.confirmedAt||
    (index&&(typeof row.assetId!=='string'||!row.assetId||row.assetId.length>256||/\s/.test(row.assetId))))return fail();
  if(policy==='arcblock-dolt-ledger/1'){
    if(!('ledgerBackend' in row)||row.ledgerBackend!==DOLT_LEDGER_BACKEND)return fail();
  }else if(!('blockHeight' in row)||typeof row.blockHeight!=='string'||!/^[1-9][0-9]*$/.test(row.blockHeight))return fail();
  return policy;
}

export function validateReceiptChainEvidence(receipt:Pick<Receipt,'payment'|'index'|'funding'>,expectedNetwork?:string):ConfirmationPolicy {
  const index=validateChainConfirmation(receipt.index,true);
  if(!receipt.index)throw new Error('Missing NFT evidence');
  if(receipt.funding){
    if(receipt.funding.mode!=='node-sponsored'||!/^did:abt:[A-Za-z0-9]+$/.test(receipt.funding.sponsorId)||! /^[1-9][0-9]*$/.test(receipt.funding.amount)||receipt.payment!==undefined||(expectedNetwork!==undefined&&receipt.index.chainId!==expectedNetwork))throw new Error('Invalid sponsored receipt');
    return index;
  }
  const payment=validateChainConfirmation(receipt.payment);
  if(!receipt.payment)throw new Error('Missing payment evidence');
  if(payment!==index||receipt.payment.chainId!==receipt.index.chainId||
    (expectedNetwork!==undefined&&receipt.payment.chainId!==expectedNetwork))throw new Error('Receipt confirmation policy or network mismatch');
  return payment;
}
