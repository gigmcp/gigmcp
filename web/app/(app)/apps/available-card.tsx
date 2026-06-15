"use client";
import Link from "next/link";
import { useTranslations } from "next-intl";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { monogram, monogramColor } from "@/lib/monogram";
import { useInstallSelf } from "@/lib/queries";
import { ApiError } from "@/lib/api";
import type { AppSummary } from "@/lib/types";

const AUTH_BADGE_VARIANT: Record<
  AppSummary["auth_type"],
  "info" | "warning" | "secondary" | "outline"
> = {
  oauth2: "info",
  api_key: "warning",
  basic: "secondary",
  custom_env: "outline",
  none: "outline",
};

export function AvailableCard({
  app,
  readOnly,
}: {
  app: AppSummary;
  readOnly: boolean;
}) {
  const t = useTranslations("apps");
  const install = useInstallSelf();

  function doInstall() {
    install.mutate(app.name, {
      onSuccess: () => toast.success(t("install.success", { name: app.display_name })),
      onError: (err) =>
        toast.error(err instanceof ApiError ? err.message : t("install.error")),
    });
  }

  return (
    <div className="flex flex-col gap-3 rounded-xl border border-border bg-card p-4">
      <Link
        href={`/apps/${app.name}`}
        className="flex items-start gap-3 rounded-lg transition-colors hover:opacity-80"
      >
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
      </Link>
      <div className="flex items-center justify-between gap-2">
        <Badge variant={AUTH_BADGE_VARIANT[app.auth_type]}>
          {t(`authType.${app.auth_type}`)}
        </Badge>
        <Button
          size="xs"
          onClick={doInstall}
          disabled={readOnly || install.isPending}
        >
          {install.isPending ? t("install.submitting") : t("install.button")}
        </Button>
      </div>
    </div>
  );
}
