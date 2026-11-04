/** Public discovery is determined only by active DIDMail node-NFT stakes.
 * Callers must obtain assetId from the configured DIDMail server factory and
 * stakes from the configured chain. HTTP metadata and sender lists are irrelevant. */
export function isPublicMailNode(
  assetId: string,
  stakes: readonly { receiver?: string; assets?: readonly string[]; revokedAssets?: readonly string[] }[],
  factoryOwner: string,
): boolean {
  const owner = (value?: string) => value && /^0x[0-9a-f]{40}$/i.test(value) ? value.toLowerCase() : value;
  return Boolean(assetId && factoryOwner && stakes.some(stake =>
    owner(stake.receiver) === owner(factoryOwner) &&
    Array.isArray(stake.assets) && stake.assets.includes(assetId) &&
    !stake.revokedAssets?.includes(assetId)
  ));
}
