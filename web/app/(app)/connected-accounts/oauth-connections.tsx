"use client";

import { useTranslations } from "next-intl";
import { useConnections, useDisconnect, useReadOnly } from "@/lib/queries";
import { oauthStartUrl } from "@/lib/api";
import { Button } from "@/components/ui/button";

/** Lists the user's OAuth connections (vendor + granted scopes) with
 *  disconnect/reconnect. Rendered on the Connected Accounts page. */
export function OAuthConnections() {
  const t = useTranslations("connections");
  const { data: connections, isLoading } = useConnections();
  const disconnect = useDisconnect();
  const readOnly = useReadOnly();

  if (isLoading) return <p className="text-sm text-muted-foreground">{t("loading")}</p>;
  const items = connections ?? [];
  if (items.length === 0)
    return <p className="text-sm text-muted-foreground">{t("noneConnected")}</p>;

  return (
    <ul className="divide-y divide-border rounded-lg border border-border">
      {items.map((c) => (
        <li key={c.vendor} className="flex items-center justify-between p-4">
          <div>
            <p className="font-medium">{c.vendor}</p>
            <p className="text-xs text-muted-foreground">
              {c.granted_scopes.length > 0 ? c.granted_scopes.join(", ") : t("noScopes")}
            </p>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={readOnly}
              onClick={() => (window.location.href = oauthStartUrl(c.vendor))}
            >
              {t("reconnect")}
            </Button>
            <Button
              variant="destructive"
              size="sm"
              disabled={readOnly}
              onClick={() => disconnect.mutate(c.vendor)}
            >
              {t("disconnect")}
            </Button>
          </div>
        </li>
      ))}
    </ul>
  );
}
