// Shared i18n constants. Importable from BOTH server and client code.
// (The server action lives in lib/locale.ts — a "use server" file may only
// export async functions, so the constants live here.)

export const LOCALES = ["en", "de", "fr", "es", "it"] as const;
export type AppLocale = (typeof LOCALES)[number];

export const DEFAULT_LOCALE: AppLocale = "en";

export const LOCALE_COOKIE = "NEXT_LOCALE";

/** Autonyms shown in the language switcher. */
export const LOCALE_NAMES: Record<AppLocale, string> = {
  en: "English",
  de: "Deutsch",
  fr: "Français",
  es: "Español",
  it: "Italiano",
};

/**
 * Message namespaces — one JSON file per namespace at
 * web/messages/<locale>/<namespace>.json. One namespace per screen plus
 * "common". A missing file is fine (falls back to en, then to {}).
 * Screen agents: add your namespace here when you add a messages file.
 */
export const NAMESPACES = [
  "common",
  "overview",
  "servers",
  "apps",
  "connectedAccounts",
  "connections",
  "profiles",
  "credentials",
  "users",
  "audit",
  "login",
  "authConfigs",
] as const;

export function isAppLocale(value: unknown): value is AppLocale {
  return (
    typeof value === "string" && (LOCALES as readonly string[]).includes(value)
  );
}
