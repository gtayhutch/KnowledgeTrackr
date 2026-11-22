/** Hosts allowed for TipTap embed nodes. Keep in sync with worker ALLOWED_EMBED_HOSTS. */
export const ALLOWED_EMBED_HOSTS = [
  "www.youtube.com",
  "youtube.com",
  "www.loom.com",
  "loom.com",
  "www.figma.com",
  "figma.com",
] as const;

/** Returns whether `url` is an https embed on an allowlisted host. */
export function isAllowedEmbedUrl(url: string): boolean {
  const trimmed = url.trim();
  if (!trimmed || trimmed.length > 2000 || /[\s\\]/.test(trimmed)) {
    return false;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "https:") return false;
    const host = parsed.hostname.toLowerCase();
    return (ALLOWED_EMBED_HOSTS as readonly string[]).includes(host);
  } catch {
    return false;
  }
}
