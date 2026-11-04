import { addressOf, amount, canonicalize, unb64u } from "./codec";
import {
  ordinaryPaymentMetadata,
  ordinaryTermsHash,
  type OrdinaryManifest,
  type OrdinaryTerms,
  type OrdinaryPaymentRequest,
} from "./ordinary";
/** Authorize the SDK-decoded transaction, after the platform has losslessly
 * decoded its protobuf Any. Never sign an uninspected node-provided payload. */
export function authorizeOrdinaryPayment(
  tx: any,
  input: {
    manifest: OrdinaryManifest;
    terms: OrdinaryTerms;
    request: OrdinaryPaymentRequest;
    publicKey: Uint8Array;
    signed?: boolean;
  },
) {
  const { manifest, terms, request, publicKey, signed = false } = input,
    settlement = terms.settlement;
  const fail = (): never => {
    throw new Error(
      "Ordinary payment differs from the explicitly accepted service terms",
    );
  };
  if (settlement.profile !== "arcblock-transfer-v3-ordinary/1") return fail();
  if (
    request.encoding !== "base64url" ||
    request.termsId !== terms.termsId ||
    request.termsSha256 !== ordinaryTermsHash(terms)
  )
    fail();
  unb64u(request.unsignedTransaction);
  const same = (v: unknown) =>
    v instanceof Uint8Array &&
    v.length === publicKey.length &&
    v.every((b, i) => b === publicKey[i]);
  const sig = (v: unknown) =>
    v === undefined || v === "" ? 0 : v instanceof Uint8Array ? v.length : -1;
  const signatures = tx.signaturesList || tx.signatures;
  if (
    tx.from !== addressOf(manifest.senderId) ||
    !same(tx.pk) ||
    tx.chainId !== terms.notification.chainId ||
    tx.delegator ||
    tx.gas ||
    (tx.receiptsList || tx.receipts || []).length ||
    amount(tx.serviceFee) !== 0n ||
    !Array.isArray(signatures) ||
    signatures.length !== 1 ||
    sig(tx.signature) !== (signed ? 64 : 0)
  )
    fail();
  const primary = signatures[0];
  if (
    primary.signer !== tx.from ||
    !same(primary.pk) ||
    primary.delegator ||
    primary.data ||
    sig(primary.signature) !== (signed ? 64 : 0)
  )
    fail();
  const itx = tx.itx;
  if (itx?.typeUrl !== "fg:t:transfer_v3") fail();
  const inputs = itx.inputsList || itx.inputs,
    outputs = itx.outputsList || itx.outputs;
  if (
    !Array.isArray(inputs) ||
    inputs.length !== 1 ||
    !Array.isArray(outputs) ||
    outputs.length !== 1
  )
    fail();
  for (const [leg, owner] of [
    [inputs[0], addressOf(manifest.senderId)],
    [outputs[0], addressOf(manifest.serviceId)],
  ] as const) {
    const tokens = leg.tokensList || leg.tokens;
    if (
      leg.owner !== owner ||
      (leg.assetsList || leg.assets || []).length ||
      !Array.isArray(tokens) ||
      tokens.length !== 1 ||
      tokens[0].address !== settlement.assetId ||
      amount(tokens[0].value) !== amount(terms.totalAmount)
    )
      fail();
  }
  if (
    itx.data?.typeUrl !== "json" ||
    canonicalize(itx.data.value) !==
      canonicalize(ordinaryPaymentMetadata(manifest, terms))
  )
    fail();
}

/** Lossless protobuf Any normalization, supplied by each platform's installed
 * SDK. Unknown/ignored wire members cannot disappear before authorization. */
export function normalizeOrdinaryTransferV3(
  tx: any,
  codec: {
    decode: (value: any) => any;
    encode: (value: any) => Uint8Array;
    fromBase64: (value: string) => Uint8Array;
  },
) {
  const any = tx.itx;
  if (any?.typeUrl !== "fg:t:transfer_v3")
    throw new Error("Unexpected ordinary payment transaction type");
  if (typeof any.value !== "string" && !(any.value instanceof Uint8Array))
    return tx;
  const wire =
      typeof any.value === "string" ? codec.fromBase64(any.value) : any.value,
    decoded = codec.decode(any);
  if (
    decoded.type !== "TransferV3Tx" ||
    decoded.value?.data?.typeUrl !== "json"
  )
    throw new Error("Invalid ordinary payment Any");
  const payload = decoded.value.data.value;
  const metadata = JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(
      typeof payload === "string" ? codec.fromBase64(payload) : payload,
    ),
  );
  const transfer = {
    ...decoded.value,
    typeUrl: "fg:t:transfer_v3",
    data: { typeUrl: "json", value: metadata },
  };
  const canonical = codec.encode({ type: "TransferV3Tx", value: transfer });
  if (
    canonical.length !== wire.length ||
    !canonical.every((b, i) => b === wire[i])
  )
    throw new Error("Noncanonical ordinary payment wire");
  return { ...tx, itx: transfer };
}
