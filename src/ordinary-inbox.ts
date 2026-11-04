import { addressOf, identityId, canonicalize, unb64u, text } from "./codec";
import {
  validateOrdinaryLocator,
  unpackOrdinaryCredential,
  type OrdinaryCredential,
} from "./ordinary";
import type { IdentityMatcher } from "./crypto";
export const ORDINARY_INBOX_QUERY =
  'query OrdinaryInbox($receiver:String!,$cursor:String!,$size:Int!){listTransactions(addressFilter:{receiver:$receiver},typeFilter:{types:["transfer_v2"]},validityFilter:{validity:VALID},paging:{cursor:$cursor,size:$size}){code page{cursor next total}transactions{hash code valid sender receiver tx{from pk chainId itxJson}}}}';
export function ordinaryInboxRequest(
  recipientId: string,
  cursor = "0",
  size = 50,
) {
  if (
    !/^(0|[1-9][0-9]{0,15})$/.test(cursor) ||
    !Number.isSafeInteger(Number(cursor)) ||
    !Number.isSafeInteger(size) ||
    size < 1 ||
    size > 100
  )
    throw new Error("Invalid ordinary inbox pagination");
  return {
    query: ORDINARY_INBOX_QUERY,
    variables: { receiver: addressOf(recipientId), cursor, size },
  };
}
/** Collection reads may omit decoded Any data; decode the bounded original
 * inner protobuf instead of silently dropping these on-chain notifications. */
export function decodeOrdinaryTransferV2Data(encoded: string): {
  to: string;
  data?: { typeUrl: string; value: unknown };
} {
  if (
    typeof encoded !== "string" ||
    encoded.length > 24 * 1024 ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)
  )
    throw new Error("Invalid encoded transfer");
  const bytes = unb64u(
    encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
  );
  if (!bytes.length || bytes.length > 16 * 1024)
    throw new Error("Invalid encoded transfer size");
  const fields = (input: Uint8Array) => {
    const values = new Map<number, Uint8Array[]>();
    let at = 0;
    const uint = () => {
      let n = 0;
      for (let i = 0; i < 5; i++) {
        if (at >= input.length) throw new Error("Truncated protobuf");
        const b = input[at++];
        n += (b & 127) * 2 ** (7 * i);
        if (b < 128) {
          if (i && b === 0) throw new Error("Noncanonical protobuf");
          return n;
        }
      }
      throw new Error("Oversized protobuf integer");
    };
    while (at < input.length) {
      const tag = uint(),
        id = Math.floor(tag / 8);
      if ((tag & 7) !== 2 || id < 1 || id > 2048)
        throw new Error("Invalid protobuf field");
      const length = uint();
      if (length > input.length - at)
        throw new Error("Truncated protobuf field");
      const list = values.get(id) || [];
      if (list.length >= 64) throw new Error("Excess protobuf fields");
      list.push(input.slice(at, at + length));
      values.set(id, list);
      at += length;
    }
    return values;
  };
  const single = (
    values: Map<number, Uint8Array[]>,
    id: number,
    required = true,
  ) => {
    const list = values.get(id) || [];
    if (list.length > 1 || (required && !list.length))
      throw new Error("Duplicate or absent protobuf field");
    return list[0];
  };
  const inner = fields(bytes),
    to = text(single(inner, 1)!),
    any = single(inner, 15, false);
  if (!any) return { to };
  const data = fields(any),
    typeUrl = text(single(data, 1)!);
  if (typeUrl !== "json" && typeUrl !== "vc") return { to };
  return { to, data: { typeUrl, value: JSON.parse(text(single(data, 2)!)) } };
}
export interface OrdinaryNoticeCandidate {
  transactionId: string;
  serviceId: string;
  messageId: string;
  manifestSha256: string;
  termsSha256: string;
  endpoint: string;
  credential: OrdinaryCredential;
}
/** Candidates from an authenticated configured RPC, not independent consensus
 * proofs. Fetch and validate the bound manifest/terms/receipt before delivery. */
export function parseOrdinaryInboxPage(
  response: unknown,
  input: {
    recipientId: string;
    chainId: string;
    cursor: string;
    limit: number;
    matches: IdentityMatcher;
  },
): {
  candidates: OrdinaryNoticeCandidate[];
  invalidTransactions: string[];
  nextCursor: string | null;
} {
  ordinaryInboxRequest(input.recipientId, input.cursor, input.limit);
  const page = (response as any)?.data?.listTransactions;
  if (
    !page ||
    !["OK", "0"].includes(String(page.code)) ||
    !Array.isArray(page.transactions) ||
    page.transactions.length > input.limit ||
    !page.page ||
    typeof page.page.next !== "boolean" ||
    typeof page.page.cursor !== "string" ||
    !/^(0|[1-9][0-9]{0,15})$/.test(page.page.cursor) ||
    !Number.isSafeInteger(Number(page.page.cursor)) ||
    (page.page.next && Number(page.page.cursor) <= Number(input.cursor)) ||
    (page.page.next && !page.transactions.length)
  )
    throw new Error("Invalid ordinary inbox page");
  const candidates: OrdinaryNoticeCandidate[] = [],
    invalidTransactions: string[] = [],
    seen = new Set<string>();
  for (const row of page.transactions) {
    const hash = row?.hash;
    if (
      typeof hash !== "string" ||
      !/^[0-9A-F]{64}$/.test(hash) ||
      seen.has(hash)
    )
      throw new Error("Invalid or repeated transaction identifier");
    seen.add(hash);
    let data = row.tx?.itxJson?.data;
    if (!data && row.tx?.itxJson?.encoded_value) {
      try {
        const decoded = decodeOrdinaryTransferV2Data(
          row.tx.itxJson.encoded_value,
        );
        if (decoded.to !== row.receiver || decoded.to !== row.tx.itxJson.to)
          throw new Error();
        data = decoded.data;
      } catch {
        invalidTransactions.push(hash);
        continue;
      }
    }
    const type = data?.typeUrl || data?.type_url || data?.type;
    if (type !== "vc" && type !== "json") continue;
    let vc = data.value;
    try {
      if (typeof vc === "string") vc = JSON.parse(vc);
    } catch {
      invalidTransactions.push(hash);
      continue;
    }
    if (type === "json") {
      if (!vc?.dmp2vc) continue;
      try {
        if (row.tx.itxJson.to !== addressOf(input.recipientId))
          throw new Error();
        vc = unpackOrdinaryCredential(vc, {
          sender: row.sender,
          recipient: row.receiver,
          publicKey: unb64u(row.tx.pk, 32),
          matches: input.matches,
        });
      } catch {
        invalidTransactions.push(hash);
        continue;
      }
    }
    if (vc?.type !== "DIDMailDeliveryCredential") continue;
    try {
      if (
        (row.tx?.itxJson?.type_url || row.tx?.itxJson?.typeUrl) !==
        "fg:t:transfer_v2"
      )
        throw new Error();
      if (
        canonicalize(vc).length > 16 * 1024 ||
        row.valid !== true ||
        !["OK", "0"].includes(String(row.code)) ||
        row.receiver !== addressOf(input.recipientId) ||
        row.sender !== row.tx.from ||
        row.tx.chainId !== input.chainId ||
        vc.issuer?.id !== row.sender
      )
        throw new Error();
      const serviceId = identityId(row.sender);
      validateOrdinaryLocator(vc, input.recipientId, serviceId, input.matches);
      const subject = vc.credentialSubject;
      candidates.push({
        transactionId: hash,
        serviceId,
        messageId: subject.messageId,
        manifestSha256: subject.manifestSha256,
        termsSha256: subject.termsSha256,
        endpoint: subject.endpoint,
        credential: vc,
      });
    } catch {
      invalidTransactions.push(hash);
    }
  }
  return {
    candidates,
    invalidTransactions,
    nextCursor: page.page.next ? page.page.cursor : null,
  };
}
