// Graceful icon fallback used everywhere an app has no registry branding (P1:
// always — no manifest carries an icon yet). Deterministic: the same slug
// always yields the same letters + background hue, so cards look stable.

/** Up to two uppercase initials from a slug ("hacker-news" → "HN", "gmail" → "GM"). */
export function monogram(slug: string): string {
  const parts = slug
    .split(/[-_\s]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) {
    return parts[0].slice(0, 2).toUpperCase();
  }
  return (parts[0][0] + parts[1][0]).toUpperCase();
}

/** Stable HSL background derived from the slug — pleasant, mid-saturation. */
export function monogramColor(slug: string): string {
  let hash = 0;
  for (let i = 0; i < slug.length; i++) {
    hash = (hash * 31 + slug.charCodeAt(i)) | 0;
  }
  const hue = Math.abs(hash) % 360;
  return `hsl(${hue} 45% 30%)`;
}
