import { cookies } from "next/headers";
import { getRequestConfig } from "next-intl/server";
import {
  DEFAULT_LOCALE,
  LOCALE_COOKIE,
  NAMESPACES,
  isAppLocale,
  type AppLocale,
} from "./config";

type Messages = Record<string, unknown>;

// Template-literal dynamic import so the bundler statically includes every
// messages/<locale>/<ns>.json that exists (required for standalone output —
// fs reads would not be traced). A file that doesn't exist throws at runtime
// and we treat it as "no messages".
async function loadNamespace(
  locale: AppLocale,
  ns: string,
): Promise<Messages | null> {
  try {
    return (await import(`../messages/${locale}/${ns}.json`)).default;
  } catch {
    return null;
  }
}

/**
 * Merge all namespace files for the active locale into one messages object:
 * { common: {...}, servers: {...}, ... } with FILE-LEVEL fallback to en —
 * a missing or unparseable namespace file for the active locale falls back
 * to the English file; if that is also missing, the namespace is omitted.
 */
async function loadMessages(locale: AppLocale): Promise<Messages> {
  const entries = await Promise.all(
    NAMESPACES.map(async (ns) => {
      const messages =
        (await loadNamespace(locale, ns)) ??
        (locale !== DEFAULT_LOCALE
          ? await loadNamespace(DEFAULT_LOCALE, ns)
          : null);
      return [ns, messages] as const;
    }),
  );
  return Object.fromEntries(entries.filter(([, m]) => m !== null));
}

// No locale routing: the active locale comes from the NEXT_LOCALE cookie
// (set by the server action in lib/locale.ts), default "en".
export default getRequestConfig(async () => {
  const store = await cookies();
  const cookieValue = store.get(LOCALE_COOKIE)?.value;
  const locale = isAppLocale(cookieValue) ? cookieValue : DEFAULT_LOCALE;

  return {
    locale,
    messages: await loadMessages(locale),
  };
});
