# Legacy attachment compatibility vectors

Status: retained historical ciphertext fixtures. Audience: compatibility-test maintainers.

`attachment-crypto-vectors.json` contains deterministic public-key/nonce inputs for the older NaCl Box attachment format. It preserves ciphertext size/hash, mail-hash and signed-download string expectations; it does not describe the current DMP/1 HPKE/chunk format.

Regenerate from the `protocol/` repository root after installing dependencies in the sibling `extension/` checkout:

```sh
node docs/protocol/fixtures/legacy-attachments/generate-attachment-vectors.mjs
```

Review byte changes rather than creating independent per-client expected hashes. Inputs are public test material and fixed nonces are intentional only for reproducible tests. Never reuse these keys/nonces for real content or funded accounts. A vector is compatibility evidence, not a cryptographic certification.

See the [active protocol index](../../README.md).
