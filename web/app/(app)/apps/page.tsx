"use client";
import { useTranslations } from "next-intl";
import { Grid3x3 } from "lucide-react";
import { useApps, useMe, useReadOnly } from "@/lib/queries";
import { Skeleton } from "@/components/ui/skeleton";
import { AppCard } from "./app-card";
import { InstallDialog } from "./install-dialog";

export default function AppsPage() {
  const t = useTranslations("apps");
  const me = useMe();
  const apps = useApps();
  const readOnly = useReadOnly();
  const isAdmin = me.data?.user.role === "admin";

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{t("title")}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{t("description")}</p>
        </div>
        {isAdmin && <InstallDialog disabled={readOnly} />}
      </div>

      {apps.isLoading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[...Array(6)].map((_, i) => (
            <Skeleton key={i} className="h-32 rounded-xl" />
          ))}
        </div>
      ) : apps.data && apps.data.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-border py-16">
          <Grid3x3 className="size-5 text-muted-foreground" aria-hidden />
          <p className="text-sm text-muted-foreground">{t("empty.title")}</p>
          {isAdmin && <InstallDialog disabled={readOnly} />}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {(apps.data ?? []).map((a) => (
            <AppCard key={a.name} app={a} />
          ))}
        </div>
      )}
    </div>
  );
}
