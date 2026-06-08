"use client";
import Link from "next/link";
import { useTranslations } from "next-intl";
import { Badge } from "@/components/ui/badge";
import { monogram, monogramColor } from "@/lib/monogram";
import type { AppSummary } from "@/lib/types";

const AUTH_BADGE_VARIANT: Record<AppSummary["auth_type"], "info" | "warning" | "secondary" | "outline"> = {
  oauth2: "info",
  api_key: "warning",
  basic: "secondary",
  custom_env: "outline",
  none: "outline",
};

/** State-aware action label key under apps.action.* */
function actionKey(app: AppSummary): string {
  if (app.connected) return "manage";
  if (app.auth_type === "oauth2") return "connectComingSoon";
  if (app.auth_type === "none") return "addToProfile";
  return "addKey"; // api_key | basic | custom_env
}

export function AppCard({ app }: { app: AppSummary }) {
  const t = useTranslations("apps");
  return (
    <Link
      href={`/apps/${app.name}`}
      className="flex flex-col gap-3 rounded-xl border border-border bg-card p-4 transition-colors hover:bg-accent"
    >
      <div className="flex items-start gap-3">
        <span
          className="flex size-10 shrink-0 items-center justify-center rounded-lg text-sm font-semibold text-white"
          style={{ backgroundColor: monogramColor(app.name) }}
          aria-hidden
        >
          {monogram(app.name)}
        </span>
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-medium">{app.display_name}</div>
          <div className="truncate text-xs text-muted-foreground">
            {app.category || t("uncategorized")}
          </div>
        </div>
      </div>
      <div className="flex items-center justify-between gap-2">
        <Badge variant={AUTH_BADGE_VARIANT[app.auth_type]}>
          {t(`authType.${app.auth_type}`)}
        </Badge>
        <span className="text-xs font-medium text-muted-foreground">
          {t(`action.${actionKey(app)}`)}
        </span>
      </div>
    </Link>
  );
}
