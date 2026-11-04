/** Limits apply to decoded response bytes, before a transport buffers the body. */
export const DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
export const MAX_RESPONSE_BYTES = DEFAULT_MAX_RESPONSE_BYTES;
export interface TransportOptions { maxResponseBytes?: number }
export type Transport = (
  url: string,
  method: string,
  headers: Record<string, string>,
  body: Uint8Array,
  options?: TransportOptions,
) => Promise<{ status: number; headers: Headers; body: Uint8Array }>;

export function responseByteLimit(options?: TransportOptions): number {
  const limit = options?.maxResponseBytes === undefined ? DEFAULT_MAX_RESPONSE_BYTES : options.maxResponseBytes;
  if (!Number.isSafeInteger(limit) || limit < 0 || limit > MAX_RESPONSE_BYTES)
    throw new Error('Invalid response byte limit');
  return limit;
}

export class ResponseLimitError extends Error {
  readonly code = 'RESPONSE_TOO_LARGE';
  constructor() { super('DMP response exceeds byte limit'); this.name = 'ResponseLimitError'; }
}

/** Browser/standards fetch only. Native transports must enforce this limit
 * before their networking bridge buffers a response, not after arrayBuffer(). */
export async function readBoundedResponse(
  response: Response,
  options?: TransportOptions,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  const limit = responseByteLimit(options);
  const source = response.body;
  if (source === null) return new Uint8Array();
  if (!source || typeof source.getReader !== 'function')
    throw new Error('A streaming response or a bounded native transport is required');
  const reader = source.getReader();
  let onAbort: (() => void) | undefined;
  let finished = false;
  try {
    if (signal?.aborted) throw signal.reason ?? new Error('Request aborted');
    const length = response.headers.get('content-length');
    if (length !== null) {
      if (!/^\d+$/.test(length) || !Number.isSafeInteger(Number(length)))
        throw new Error('Invalid response content length');
      // Fetch transparently decodes content. Compressed Content-Length can be
      // larger OR smaller than the decoded bytes, so count the decoded stream.
      const encoding = response.headers.get('content-encoding')?.trim().toLowerCase();
      if ((!encoding || encoding === 'identity') && Number(length) > limit)
        throw new ResponseLimitError();
    }
    const aborted = signal ? new Promise<never>((_, reject) => {
      onAbort = () => reject(signal.reason ?? new Error('Request aborted'));
      signal.addEventListener('abort', onAbort, { once: true });
    }) : undefined;
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const part = await (aborted ? Promise.race([reader.read(), aborted]) : reader.read());
      if (part.done) break;
      if (!(part.value instanceof Uint8Array)) throw new Error('Invalid response byte stream');
      if (part.value.byteLength > limit - size) throw new ResponseLimitError();
      size += part.value.byteLength;
      // Retain only owned, bounded buffers. A small view must not retain an
      // arbitrarily large backing allocation or mutable stream producer data.
      if (part.value.byteLength) chunks.push(new Uint8Array(part.value));
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const part of chunks) { bytes.set(part, offset); offset += part.length; }
    finished = true;
    return bytes;
  } finally {
    if (signal && onAbort) signal.removeEventListener('abort', onAbort);
    // A hostile/nonconforming source can leave cancellation pending forever.
    // Do not wait for it before rejecting the over-limit request.
    if (!finished) void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export const fetchTransport: Transport = async (url, method, headers, body, options) => {
  responseByteLimit(options); // Invalid caller limits must fail before dispatch.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), method === 'PUT' && headers['content-type'] === 'application/octet-stream' ? 60000 : 20000);
  let response: Response | undefined;
  try {
    response = await fetch(url, {
      method, headers,
      body: ['GET', 'HEAD'].includes(method) ? undefined : new Uint8Array(body).buffer,
      signal: controller.signal, redirect: 'error',
    });
    if ((response.status >= 300 && response.status < 400) || response.redirected || (response.url && new URL(response.url).href !== new URL(url).href))
      throw new Error('DMP service redirects are not allowed');
    const bytes = await readBoundedResponse(response, options, controller.signal);
    return { status: response.status, headers: response.headers, body: bytes };
  } catch (error) {
    controller.abort();
    if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
    throw error;
  } finally { clearTimeout(timer); }
};
