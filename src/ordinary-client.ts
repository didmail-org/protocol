import { canonicalize, utf8, text, unb64u, digest } from "./codec";
import { signRequest } from "./auth";
import { keyIdOf, encryptionPublicKey } from "./crypto";
import {
  DmpClient,
  DmpError,
  fetchTransport,
  type ClientOptions,
  type Progress,
} from "./client";
import { decodeDocument, type PlainAttachment } from "./message";
import { confirmationPolicy } from "./chain-confirmation";
import {
  ordinaryOrigin,
  ordinaryManifestHash,
  ordinaryTermsHash,
  sealOrdinaryMessage,
  decryptOrdinaryBlob,
  validateOrdinaryManifest,
  validateOrdinaryLimits,
  validateOrdinaryTerms,
  validateOrdinaryReceipt,
  type OrdinaryManifest,
  type OrdinaryTerms,
  type OrdinaryReceipt,
  type OrdinaryCredential,
  type OrdinaryLimits,
  type OrdinaryPaymentRequest,
} from "./ordinary";
import {
  ordinaryInboxRequest,
  parseOrdinaryInboxPage,
  type OrdinaryNoticeCandidate,
} from "./ordinary-inbox";

export interface OrdinaryStatus {
  messageId: string;
  state:
    | "uploading"
    | "queued"
    | "notification_pending"
    | "payment_pending"
    | "payment_confirmed"
    | "delivered"
    | "reconciliation_required"
    | "expired"
    | "rejected";
  revision: number;
  updatedAt: string;
  acceptedAt?: string;
  notificationTransactionId?: string;
  paymentTransactionId?: string;
  receipt?: OrdinaryReceipt;
}
export interface OrdinaryBundle {
  manifest: OrdinaryManifest;
  terms: OrdinaryTerms;
  receipt: OrdinaryReceipt;
  credential: OrdinaryCredential;
}
export interface OrdinaryTask {
  endpoint: string;
  manifest: OrdinaryManifest;
  chunks: Record<string, string[]>;
  terms?: OrdinaryTerms;
  status?: OrdinaryStatus;
  paymentRequest?: OrdinaryPaymentRequest;
  signedPayment?: string;
  acceptance?: {
    expectedRevision: number;
    termsId: string;
    termsSha256: string;
    signedPayment?: string;
  };
}
export interface OrdinaryTaskStore {
  put(task: OrdinaryTask): Promise<void>;
  get(messageId: string): Promise<OrdinaryTask | undefined>;
  remove(messageId: string): Promise<void>;
}
export interface OrdinaryConfig {
  protocolVersion: 2;
  available: boolean;
  experimental: true;
  serviceId: string;
  apiBaseUrl: string;
  policyRevision: number;
  signingKey: { keyId: string; publicKey: string; serviceId: string };
  plan: { planId: "ordinary"; totalAmount: string; retentionSeconds: number };
  notification: OrdinaryTerms["notification"];
  limits: OrdinaryLimits;
}
export type OrdinaryClientOptions = Omit<ClientOptions, "store"> & {
  store: OrdinaryTaskStore;
};
/** Ordinary mail uses the same key registry and encrypted key archives as DMP/1.
 * Acceptance is persisted before I/O, so retries never silently accept new terms. */
export class OrdinaryClient {
  readonly endpoint: string;
  private config?: OrdinaryConfig;
  private readonly keys: DmpClient;
  constructor(private readonly options: OrdinaryClientOptions) {
    this.endpoint = ordinaryOrigin(options.endpoint);
    this.keys = new DmpClient({
      ...options,
      store: {
        put: async () => {
          throw new Error("Wrong task store");
        },
        get: async () => undefined,
        remove: async () => {},
      },
    });
  }
  private async request(
    path: string,
    method = "GET",
    value?: unknown,
    binary = false,
    publicRead = false,
  ) {
    const url = this.endpoint + path,
      body =
        value === undefined
          ? new Uint8Array()
          : binary
            ? (value as Uint8Array)
            : utf8(canonicalize(value));
    const headers: Record<string, string> = {
      accept: binary ? "application/octet-stream" : "application/json",
    };
    if (method !== "GET")
      headers["content-type"] = binary
        ? "application/octet-stream"
        : "application/json";
    if (!publicRead)
      Object.assign(
        headers,
        signRequest(
          method,
          url,
          body,
          this.options.identityId,
          this.options.secretKey,
        ),
      );
    const r = await (this.options.transport || fetchTransport)(
      url,
      method,
      headers,
      body,
    );
    if (r.status >= 400) {
      let problem;
      try {
        problem = JSON.parse(text(r.body));
      } catch {
        problem = {
          status: r.status,
          code: "SERVICE_UNAVAILABLE",
          detail: "Ordinary mail request failed",
          recoveryAction: "query_status",
        };
      }
      throw new DmpError(problem);
    }
    return r.body;
  }
  private async json<T>(
    path: string,
    method = "GET",
    value?: unknown,
    publicRead = false,
  ): Promise<T> {
    return JSON.parse(
      text(await this.request(path, method, value, false, publicRead)),
    );
  }
  async connect(): Promise<OrdinaryConfig> {
    const d = await this.json<OrdinaryConfig>(
        "/v2/ordinary/service-config",
        "GET",
        undefined,
        true,
      ),
      expected = this.options.expectedChain;
    if (
      d.protocolVersion !== 2 ||
      d.experimental !== true ||
      typeof d.available !== "boolean" ||
      !Number.isSafeInteger(d.policyRevision) ||
      d.policyRevision < 1 ||
      d.apiBaseUrl !== this.endpoint + "/v2/ordinary" ||
      d.signingKey?.serviceId !== d.serviceId ||
      keyIdOf(unb64u(d.signingKey.publicKey, 32)) !== d.signingKey.keyId ||
      !this.options.matches(unb64u(d.signingKey.publicKey, 32), d.serviceId) ||
      d.plan?.planId !== "ordinary" ||
      !/^(0|[1-9][0-9]{0,77})$/.test(d.plan.totalAmount) ||
      !Number.isSafeInteger(d.plan.retentionSeconds) ||
      d.plan.retentionSeconds < 86400 ||
      d.notification?.profile !== "arcblock-transfer-v2-vc/1"
    )
      throw new Error("Invalid ordinary service configuration");
    const policy = confirmationPolicy(d.notification.confirmationPolicy);
    if (
      expected &&
      (d.notification.chainId !== expected.chainId ||
        d.notification.chainEndpoint.replace(/\/+$/, "") !==
          expected.chainEndpoint.replace(/\/+$/, "") ||
        !(expected.confirmationPolicies ?? ["arcblock-committed"]).includes(
          policy,
        ))
    )
      throw new Error("Ordinary chain profile differs from this client");
    validateOrdinaryLimits(d.limits);
    await this.options.pinService(d.serviceId, d.signingKey.publicKey);
    this.config = d;
    return d;
  }
  async eligibility() {
    const result = await this.json<{
      gas: {
        minimumUnits: string;
        node: { eligible: boolean };
        sender: { eligible: boolean };
      };
    }>("/v1/sending-eligibility");
    if (
      !result.gas ||
      !/^[1-9][0-9]*$/.test(result.gas.minimumUnits) ||
      typeof result.gas.node?.eligible !== "boolean" ||
      typeof result.gas.sender?.eligible !== "boolean"
    )
      throw new Error("Gas stake eligibility is unavailable");
    const node = result.gas.node.eligible,
      sender = result.gas.sender.eligible;
    if (!node || !sender)
      throw new DmpError({
        type: "about:blank",
        status: 403,
        title: "Gas stake required",
        code: !node ? "NODE_GAS_STAKE_REQUIRED" : "SENDER_GAS_STAKE_REQUIRED",
        detail: !node
          ? "The node must self-stake at least one native token before sending. Contact its operator."
          : `Self-stake at least one native token for fee-free transactions (current chain minimum: ${result.gas.minimumUnits} atomic units). Open account staking and then retry.`,
        requestId: "",
        recoveryAction: !node ? "contact_operator" : "stake_for_gas",
      });
    return result;
  }
  async create(
    input: {
      recipientId: string;
      subject: string;
      body: string;
      mediaType?: "text/plain" | "text/html";
      attachments?: PlainAttachment[];
    },
    progress?: Progress,
  ): Promise<OrdinaryTask> {
    const config = await this.connect();
    if (!config.available)
      throw new Error("Ordinary mail is not enabled on this node");
    await this.eligibility();
    const senderKey = await this.keys.ensureReceivingKey(),
      recipientKey =
        input.recipientId === this.options.identityId
          ? senderKey
          : await this.keys.recipientKey(input.recipientId);
    progress?.("encrypting");
    const sealed = sealOrdinaryMessage({
      ...input,
      senderId: this.options.identityId,
      serviceId: config.serviceId,
      secretKey: this.options.secretKey,
      senderKey,
      recipientKey,
      matches: this.options.matches,
    });
    const task: OrdinaryTask = { ...sealed, endpoint: this.endpoint };
    this.checkLimits(task.manifest, config.limits);
    await this.options.store.put(task);
    return task;
  }
  private checkLimits(manifest: OrdinaryManifest, limits: OrdinaryLimits) {
    const files = manifest.blobs.filter(
      (b) => b.blobId !== manifest.documentBlobId,
    );
    if (
      (!limits.enabled && files.length) ||
      files.length > limits.maxCount ||
      files.some(
        (b) => b.sizeBytes - 16 * b.chunkCount > limits.maxFileBytes,
      ) ||
      files.reduce((s, b) => s + b.sizeBytes - 16 * b.chunkCount, 0) >
        limits.maxTotalBytes ||
      manifest.blobs.reduce((s, b) => s + b.sizeBytes, 0) >
        limits.maxMessageCiphertextBytes
    )
      throw new Error("Message exceeds node attachment or storage limits");
  }
  private owner(task: OrdinaryTask) {
    if (
      task.endpoint !== this.endpoint ||
      task.manifest.senderId !== this.options.identityId
    )
      throw new Error("Ordinary task owner/service mismatch");
  }
  private checkTerms(
    terms: OrdinaryTerms,
    manifest: OrdinaryManifest,
    allowExpired = false,
  ) {
    validateOrdinaryTerms(
      terms,
      manifest,
      this.options.matches,
      Date.now(),
      allowExpired,
    );
    const config = this.config;
    if (
      !config ||
      terms.serviceId !== config.serviceId ||
      terms.serviceEndpoint !== this.endpoint ||
      canonicalize(terms.notification) !== canonicalize(config.notification)
    )
      throw new Error("Ordinary terms service snapshot mismatch");
    if (
      terms.settlement.profile !== "none" &&
      this.options.expectedChain &&
      terms.settlement.assetId !== this.options.expectedChain.paymentAssetId
    )
      throw new Error("Ordinary service payment uses a different native token");
    if (
      !allowExpired &&
      (terms.policyRevision !== config.policyRevision ||
        terms.retentionSeconds !== config.plan.retentionSeconds)
    )
      throw new Error(
        "Ordinary policy changed; refresh and review service terms",
      );
    this.checkLimits(manifest, terms.limits);
  }
  async prepare(
    task: OrdinaryTask,
    progress?: Progress,
  ): Promise<OrdinaryTerms> {
    this.owner(task);
    await this.connect();
    const session = await this.json<{
      terms: OrdinaryTerms;
      status: OrdinaryStatus;
      missingChunks: { blobId: string; index: number }[];
    }>(
      `/v2/ordinary/messages/${task.manifest.messageId}`,
      "PUT",
      task.manifest,
    );
    this.checkTerms(session.terms, task.manifest, !!session.status.acceptedAt);
    if (
      task.acceptance &&
      task.acceptance.termsSha256 !== ordinaryTermsHash(session.terms)
    )
      throw new Error("Previously accepted ordinary terms changed");
    task.terms = session.terms;
    task.status = session.status;
    await this.options.store.put(task);
    const missing = session.missingChunks;
    if (!Array.isArray(missing)) throw new Error("Invalid missing chunks");
    for (let completed = 0; completed < missing.length; completed++) {
      const c = missing[completed],
        descriptor = task.manifest.blobs.find((b) => b.blobId === c.blobId);
      if (
        !descriptor ||
        !Number.isSafeInteger(c.index) ||
        c.index < 0 ||
        c.index >= descriptor.chunkCount ||
        !task.chunks[c.blobId]?.[c.index]
      )
        throw new Error("Invalid missing chunk locator");
      await this.request(
        `/v2/ordinary/messages/${task.manifest.messageId}/blobs/${c.blobId}/chunks/${c.index}`,
        "PUT",
        unb64u(task.chunks[c.blobId][c.index]),
        true,
      );
      progress?.("uploading", completed + 1, missing.length);
    }
    if (
      session.terms.settlement.profile !== "none" &&
      !session.status.acceptedAt
    ) {
      const prepared = await this.json<{
        paymentRequest: OrdinaryPaymentRequest;
        status: OrdinaryStatus;
      }>(
        `/v2/ordinary/messages/${task.manifest.messageId}/prepare-payment`,
        "POST",
        {
          expectedRevision: task.status!.revision,
          termsId: session.terms.termsId,
          termsSha256: ordinaryTermsHash(session.terms),
        },
      );
      if (
        prepared.paymentRequest.termsId !== session.terms.termsId ||
        prepared.paymentRequest.termsSha256 !==
          ordinaryTermsHash(session.terms) ||
        prepared.paymentRequest.encoding !== "base64url"
      )
        throw new Error("Payment preparation does not bind accepted terms");
      task.paymentRequest = prepared.paymentRequest;
      task.status = prepared.status;
      await this.options.store.put(task);
    }
    return session.terms;
  }
  /** Refresh is explicit, only before acceptance, with the original CAS revision. */
  async refreshTerms(task: OrdinaryTask): Promise<OrdinaryTerms> {
    this.owner(task);
    if (task.acceptance || task.signedPayment || !task.status || !task.terms)
      throw new Error("Cannot replace accepted terms");
    await this.connect();
    const r = await this.json<{ terms: OrdinaryTerms; status: OrdinaryStatus }>(
      `/v2/ordinary/messages/${task.manifest.messageId}/terms`,
      "POST",
      {
        expectedRevision: task.status.revision,
        previousTermsId: task.terms.termsId,
      },
    );
    this.checkTerms(r.terms, task.manifest);
    task.terms = r.terms;
    task.status = r.status;
    task.paymentRequest = undefined;
    await this.options.store.put(task);
    return r.terms;
  }
  async submit(
    task: OrdinaryTask,
    signedPayment?: string,
  ): Promise<OrdinaryStatus> {
    this.owner(task);
    if (!task.terms || !task.status)
      throw new Error("Prepare the original task first");
    if (signedPayment) {
      if (task.signedPayment && task.signedPayment !== signedPayment)
        throw new Error("Original payment conflict");
      task.signedPayment = signedPayment;
    }
    if (!task.acceptance) {
      this.checkTerms(task.terms, task.manifest);
      if (
        task.terms.settlement.profile !== "none" &&
        (!task.paymentRequest || !task.signedPayment)
      )
        throw new Error(
          "Explicitly authorized original service payment required",
        );
      task.acceptance = {
        expectedRevision: task.status.revision,
        termsId: task.terms.termsId,
        termsSha256: ordinaryTermsHash(task.terms),
        ...(task.terms.settlement.profile === "none"
          ? {}
          : { signedPayment: task.signedPayment }),
      };
      await this.options.store.put(task);
    }
    try {
      const status = await this.json<OrdinaryStatus>(
        `/v2/ordinary/messages/${task.manifest.messageId}/submit`,
        "POST",
        task.acceptance,
      );
      this.checkStatus(status, task.manifest.messageId);
      task.status = status;
      await this.options.store.put(task);
      return status;
    } catch (error) {
      if (error instanceof DmpError && error.problem.status < 500) throw error;
      try {
        const s = await this.status(task.manifest.messageId);
        if (s.acceptedAt) {
          task.status = s;
          await this.options.store.put(task);
          return s;
        }
      } catch {
        /* Original acceptance remains durable. */
      }
      throw error;
    }
  }
  private checkStatus(s: OrdinaryStatus, id: string) {
    if (
      s.messageId !== id ||
      !Number.isSafeInteger(s.revision) ||
      s.revision < 1 ||
      ![
        "uploading",
        "queued",
        "notification_pending",
        "payment_pending",
        "payment_confirmed",
        "delivered",
        "reconciliation_required",
        "expired",
        "rejected",
      ].includes(s.state) ||
      !Number.isFinite(Date.parse(s.updatedAt))
    )
      throw new Error("Invalid ordinary status");
  }
  async status(id: string): Promise<OrdinaryStatus> {
    const s = await this.json<OrdinaryStatus>(
      `/v2/ordinary/messages/${id}/status`,
    );
    this.checkStatus(s, id);
    return s;
  }
  async resume(id: string): Promise<OrdinaryStatus> {
    const task = await this.options.store.get(id);
    if (!task) throw new Error("Original encrypted ordinary task required");
    this.owner(task);
    const s = await this.status(id);
    if (s.acceptedAt) {
      task.status = s;
      await this.options.store.put(task);
      return s;
    }
    if (!task.acceptance) await this.prepare(task);
    return this.submit(task);
  }
  async readBundle(id: string): Promise<OrdinaryBundle> {
    await this.connect();
    const bundle = await this.json<OrdinaryBundle>(
      `/v2/ordinary/messages/${id}`,
    );
    validateOrdinaryReceipt(
      bundle.receipt,
      bundle.manifest,
      bundle.terms,
      bundle.credential,
      this.options.matches,
    );
    if (
      bundle.manifest.messageId !== id ||
      bundle.manifest.serviceId !== this.config!.serviceId ||
      ![bundle.manifest.senderId, bundle.manifest.recipientId].includes(
        this.options.identityId,
      )
    )
      throw new Error("Ordinary download identity mismatch");
    this.checkTerms(bundle.terms, bundle.manifest, true);
    return bundle;
  }
  async bundle(candidate: OrdinaryNoticeCandidate): Promise<OrdinaryBundle> {
    if (candidate.endpoint !== this.endpoint)
      throw new Error("Cross-node locator endpoint mismatch");
    const bundle = await this.readBundle(candidate.messageId);
    const { manifest, terms, receipt, credential } = bundle;
    this.checkTerms(terms, manifest, true);
    if (
      this.config!.serviceId !== candidate.serviceId ||
      manifest.recipientId !== this.options.identityId ||
      manifest.messageId !== candidate.messageId ||
      ordinaryManifestHash(manifest) !== candidate.manifestSha256 ||
      ordinaryTermsHash(terms) !== candidate.termsSha256 ||
      canonicalize(credential) !== canonicalize(candidate.credential) ||
      receipt.notification.transaction.transactionId !== candidate.transactionId
    )
      throw new Error("Chain notification differs from delivery bundle");
    return bundle;
  }
  async blob(bundle: OrdinaryBundle, blobId: string): Promise<Uint8Array> {
    if (!this.config) await this.connect();
    validateOrdinaryReceipt(
      bundle.receipt,
      bundle.manifest,
      bundle.terms,
      bundle.credential,
      this.options.matches,
    );
    const { manifest, terms, receipt } = bundle;
    if (
      terms.serviceEndpoint !== this.endpoint ||
      ![manifest.recipientId, manifest.senderId].includes(
        this.options.identityId,
      )
    )
      throw new Error("Download owner or origin mismatch");
    validateOrdinaryManifest(
      manifest,
      this.options.matches,
      Date.parse(receipt.acceptedAt),
    );
    const blob = manifest.blobs.find((b) => b.blobId === blobId);
    if (!blob) throw new Error("Unknown ordinary blob");
    const chunks: Uint8Array[] = [];
    for (let i = 0; i < blob.chunkCount; i++)
      chunks.push(
        await this.request(
          `/v2/ordinary/messages/${manifest.messageId}/blobs/${blobId}/chunks/${i}`,
        ),
      );
    const envelope = manifest.keyEnvelopes.find(
      (k) => k.ownerId === this.options.identityId,
    );
    let secret: Uint8Array | undefined;
    try {
      const store = this.options.keys;
      if (store && envelope) {
        if (store.lookup) {
          const pair = await store.lookup(envelope.keyRecord.keyId);
          if (pair) {
            secret = pair.secret;
            if (canonicalize(pair.record) !== canonicalize(envelope.keyRecord))
              throw new Error("Historic encryption key record mismatch");
          }
        } else {
          const records = await store.records();
          const record = records.find(
            (r) => r.keyId === envelope.keyRecord.keyId,
          );
          if (record) {
            if (canonicalize(record) !== canonicalize(envelope.keyRecord))
              throw new Error("Historic encryption key record mismatch");
            secret = await store.secret(record.keyId);
            if (!secret) throw new Error("Historic private key required");
          }
        }
        if (
          secret &&
          (secret.length !== 32 ||
            keyIdOf(encryptionPublicKey(secret)) !== envelope.keyRecord.keyId)
        )
          throw new Error("Invalid archived encryption key");
      }
      return decryptOrdinaryBlob(
        manifest,
        blobId,
        chunks,
        this.options.identityId,
        this.options.secretKey,
        this.options.matches,
        receipt.acceptedAt,
        secret,
      );
    } finally {
      secret?.fill(0);
    }
  }
  async document(bundle: OrdinaryBundle) {
    return decodeDocument(
      await this.blob(bundle, bundle.manifest.documentBlobId),
    );
  }
}

/** Bounded pages are scanned from the chain head each cycle. Persisted retries
 * contain only verified locators; advance a page only after durable handling.
 * Offset indexes are mutable, so a completed cycle must restart at zero. */
export interface OrdinaryInboxCheckpoint {
  cursor: string;
  cycle: number;
  pending: OrdinaryNoticeCandidate[];
}
export const ordinaryCandidateId = (c: OrdinaryNoticeCandidate) =>
  digest(
    utf8(
      canonicalize({
        serviceId: c.serviceId,
        messageId: c.messageId,
        transactionId: c.transactionId,
      }),
    ),
  );

export interface OrdinaryInboxStore {
  load(): Promise<OrdinaryInboxCheckpoint | undefined>;
  save(checkpoint: OrdinaryInboxCheckpoint): Promise<void>;
  has(id: string): Promise<boolean>;
  /** Commit mailbox content and its processed ID atomically. */
  deliver(candidate: OrdinaryNoticeCandidate): Promise<void>;
}
export async function syncOrdinaryInbox(input: {
  recipientId: string;
  chainId: string;
  matches: ClientOptions["matches"];
  store: OrdinaryInboxStore;
  query: (request: ReturnType<typeof ordinaryInboxRequest>) => Promise<unknown>;
  maxPages?: number;
}) {
  let checkpoint = (await input.store.load()) || {
    cursor: "0",
    cycle: 0,
    pending: [],
  };
  let delivered = 0;
  const drain = async () => {
    const pending: OrdinaryNoticeCandidate[] = [];
    for (const candidate of checkpoint.pending) {
      if (await input.store.has(ordinaryCandidateId(candidate))) continue;
      try {
        await input.store.deliver(candidate);
        delivered++;
      } catch {
        pending.push(candidate);
      }
    }
    checkpoint = { ...checkpoint, pending };
    await input.store.save(checkpoint);
  };
  await drain();
  // Backpressure retains failed origin downloads without unbounded local growth.
  for (
    let page = 0;
    page < (input.maxPages ?? 4) && checkpoint.pending.length < 200;
    page++
  ) {
    const cursor = checkpoint.cursor;
    const result = parseOrdinaryInboxPage(
      await input.query(ordinaryInboxRequest(input.recipientId, cursor, 50)),
      {
        recipientId: input.recipientId,
        chainId: input.chainId,
        cursor,
        limit: 50,
        matches: input.matches,
      },
    );
    const candidates = new Map(
      checkpoint.pending.map((c) => [ordinaryCandidateId(c), c]),
    );
    for (const c of result.candidates)
      if (!(await input.store.has(ordinaryCandidateId(c))))
        candidates.set(ordinaryCandidateId(c), c);
    // Persist locator and pagination together before attempting any origin I/O.
    checkpoint = {
      cursor: result.nextCursor || "0",
      cycle: checkpoint.cycle + (result.nextCursor ? 0 : 1),
      pending: [...candidates.values()],
    };
    await input.store.save(checkpoint);
    await drain();
    if (!result.nextCursor) break;
  }
  return {
    delivered,
    pending: checkpoint.pending.length,
    cycle: checkpoint.cycle,
  };
}
