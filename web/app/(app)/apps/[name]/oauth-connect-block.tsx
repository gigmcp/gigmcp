"use client";

import { useTranslations } from "next-intl";
import { useConnections, useReadOnly } from "@/lib/queries";
import { oauthStartUrl } from "@/lib/api";
import { Button } from "@/components/ui/button";

/** Renders the live OAuth connect block for an app whose manifest credential is
 *  oauth2. `vendor` is the manifest vendor key; `server` is the app slug (so the
 *  start endpoint can compute the scope union); `requiredScopes` come from the
 *  manifest and drive the incremental-consent hint. */
export function OAuthConnectBlock({
  vendor,
  server,
  requiredScopes,
}: {
  vendor: string;
  server: string;
  requiredScopes: string[];
}) {
  const t = useTranslations("connections");
  const { data: connections } = useConnections();
  const readOnly = useReadOnly();

  const conn = (connections ?? []).find((c) => c.vendor === vendor);
  const granted = new Set(conn?.granted_scopes ?? []);
  const missing = requiredScopes.filter((s) => !granted.has(s));
  const needsIncremental = conn != null && missing.length > 0;

  const connect = () => {
    // Top-level navigation so the browser follows the cross-origin 302.
    window.location.href = oauthStartUrl(vendor, server);
  };

  if (!conn) {
    return (
      <div className="rounded-lg border border-border p-4">
        <p className="text-sm">{t("connectPrompt", { vendor })}</p>
        <Button className="mt-3" disabled={readOnly} onClick={connect}>
          {t("connect", { vendor })}
        </Button>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border p-4">
      <p className="text-sm font-medium text-green-600">{t("connected", { vendor })}</p>
      {needsIncremental && (
        <p className="mt-2 text-sm text-amber-600">
          {t("incrementalConsent", { scopes: missing.join(", ") })}
        </p>
      )}
      <Button
        variant={needsIncremental ? "default" : "outline"}
        className="mt-3"
        disabled={readOnly}
        onClick={connect}
      >
        {needsIncremental ? t("grantMore") : t("reconnect")}
      </Button>
    </div>
  );
}
