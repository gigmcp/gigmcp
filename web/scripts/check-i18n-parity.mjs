#!/usr/bin/env node
// i18n parity guard — committed automated check (Task 18, Step 5 made durable).
//
// next-intl loads one JSON file per namespace per locale and resolves keys at
// RENDER time. A dropped key or a mangled ICU placeholder ({vendor}/{scopes})
// in a non-English locale therefore throws only when that screen renders in
// that language — never at build time. This script fails CI instead, by
// asserting, for every namespace file, that each non-English locale has:
//   1. exactly the same set of leaf keys as English, and
//   2. the same set of ICU placeholders in each value as English.
//
// Runs with zero dependencies via `node`; wired into `pnpm run lint` and CI.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const messagesDir = join(here, "..", "messages");

const DEFAULT_LOCALE = "en";
const locales = readdirSync(messagesDir, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name);

if (!locales.includes(DEFAULT_LOCALE)) {
  console.error(`FATAL: no '${DEFAULT_LOCALE}' locale under ${messagesDir}`);
  process.exit(1);
}

const errors = [];

// Flatten a messages object into { "a.b.c": "value" } for leaf string values.
function flatten(obj, prefix = "") {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      Object.assign(out, flatten(v, key));
    } else {
      out[key] = v;
    }
  }
  return out;
}

// Extract the multiset of ICU placeholder names from a string, e.g.
// "needs {scopes}. Reconnect {vendor}" -> ["scopes", "vendor"] (sorted).
function placeholders(value) {
  if (typeof value !== "string") return [];
  const names = [];
  for (const m of value.matchAll(/\{\s*([a-zA-Z0-9_]+)\s*[,}]/g)) {
    names.push(m[1]);
  }
  return names.sort();
}

function load(locale, ns) {
  const path = join(messagesDir, locale, `${ns}.json`);
  return flatten(JSON.parse(readFileSync(path, "utf8")));
}

const namespaces = readdirSync(join(messagesDir, DEFAULT_LOCALE))
  .filter((f) => f.endsWith(".json"))
  .map((f) => f.replace(/\.json$/, ""));

let checks = 0;
for (const ns of namespaces) {
  const en = load(DEFAULT_LOCALE, ns);
  const enKeys = Object.keys(en).sort();

  for (const locale of locales) {
    if (locale === DEFAULT_LOCALE) continue;
    const path = join(messagesDir, locale, `${ns}.json`);
    if (!existsSync(path)) continue; // file-level fallback to en is allowed.

    checks++;
    const loc = load(locale, ns);
    const locKeys = Object.keys(loc).sort();

    const missing = enKeys.filter((k) => !(k in loc));
    const extra = locKeys.filter((k) => !(k in en));
    if (missing.length) {
      errors.push(`${locale}/${ns}: missing keys: ${missing.join(", ")}`);
    }
    if (extra.length) {
      errors.push(`${locale}/${ns}: extra keys not in en: ${extra.join(", ")}`);
    }

    for (const k of enKeys) {
      if (!(k in loc)) continue;
      const want = placeholders(en[k]).join(",");
      const got = placeholders(loc[k]).join(",");
      if (want !== got) {
        errors.push(
          `${locale}/${ns}: key "${k}" placeholder mismatch — en {${want}} vs ${locale} {${got}}`,
        );
      }
    }
  }
}

if (errors.length) {
  console.error("i18n parity check FAILED:");
  for (const e of errors) console.error(`  - ${e}`);
  process.exit(1);
}

console.log(
  `i18n parity OK — ${namespaces.length} namespaces × ${locales.length - 1} non-en locales, ${checks} files checked.`,
);
