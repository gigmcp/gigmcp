"use server";

// Server action: persist the dashboard language in the NEXT_LOCALE cookie.
// NO app/api route handlers may exist (they'd shadow the /api/* rewrite to
// the Go gateway), so cookie writes go through this action. Locale constants
// + autonyms live in @/i18n/config ("use server" files may only export async
// functions).

import { cookies } from "next/headers";
import { LOCALE_COOKIE, isAppLocale } from "@/i18n/config";

export async function setLocale(locale: string): Promise<void> {
  if (!isAppLocale(locale)) return;
  const store = await cookies();
  store.set(LOCALE_COOKIE, locale, {
    path: "/",
    maxAge: 60 * 60 * 24 * 365,
    sameSite: "lax",
  });
}
