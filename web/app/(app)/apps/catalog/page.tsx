"use client";
import { useMemo, useState } from "react";
import { useTranslations } from "next-intl";
import {
  PackageOpenIcon,
  SearchIcon,
  ShieldAlertIcon,
  TriangleAlertIcon,
} from "lucide-react";
import { toast } from "sonner";
import {
  useApps,
  useCatalog,
  useInstallServer,
  useMe,
  useReadOnly,
  useUninstallServer,
} from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { monogram, monogramColor } from "@/lib/monogram";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import type { CatalogServer } from "@/lib/types";

function CatalogCard({
  server,
  allowListed,
  readOnly,
}: {
  server: CatalogServer;
  allowListed: boolean;
  readOnly: boolean;
}) {
  const t = useTranslations("apps");
  const install = useInstallServer();
  const uninstall = useUninstallServer();
  const pending = install.isPending || uninstall.isPending;

  function doInstall() {
    install.mutate(server.name, {
      onSuccess: (s) =>
        toast.success(t("install.success", { name: s.name || server.name })),
      onError: (err) =>
        toast.error(err instanceof ApiError ? err.message : t("install.error")),
    });
  }

  function doRemove() {
    uninstall.mutate(server.name, {
      onSuccess: () =>
        toast.success(
          t("catalog.removed", { name: server.display_name || server.name }),
        ),
      onError: (err) =>
        toast.error(
          err instanceof ApiError ? err.message : t("catalog.removeError"),
        ),
    });
  }

  return (
    <div className="flex flex-col gap-3 rounded-xl border border-border bg-card p-4">
      <div className="flex items-start gap-3">
        <span
          className="flex size-10 shrink-0 items-center justify-center rounded-lg text-sm font-semibold text-white"
          style={{ backgroundColor: monogramColor(server.name) }}
          aria-hidden
        >
          {monogram(server.name)}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-medium">
              {server.display_name || server.name}
            </span>
            {allowListed && (
              <Badge variant="success">{t("catalog.allowListedBadge")}</Badge>
            )}
          </div>
          {server.description && (
            <p className="mt-0.5 line-clamp-2 text-xs text-muted-foreground">
              {server.description}
            </p>
          )}
        </div>
      </div>
      <div className="flex items-center justify-between gap-2">
        <Badge variant="outline" className="font-mono">
          {server.latest}
        </Badge>
        {allowListed ? (
          <Button
            variant="outline"
            size="xs"
            onClick={doRemove}
            disabled={readOnly || pending}
          >
            {uninstall.isPending
              ? t("catalog.removing")
              : t("catalog.remove")}
          </Button>
        ) : (
          <Button size="xs" onClick={doInstall} disabled={readOnly || pending}>
            {install.isPending ? t("install.submitting") : t("catalog.add")}
          </Button>
        )}
      </div>
    </div>
  );
}

function CardSkeletons() {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {[...Array(6)].map((_, i) => (
        <Skeleton key={i} className="h-32 rounded-xl" />
      ))}
    </div>
  );
}

export default function CatalogPage() {
  const t = useTranslations("apps");
  const me = useMe();
  const readOnly = useReadOnly();
  const catalog = useCatalog();
  const apps = useApps();
  const [search, setSearch] = useState("");

  const allowListed = useMemo(
    () => new Set((apps.data ?? []).map((a) => a.name)),
    [apps.data],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const all = catalog.data ?? [];
    if (!q) return all;
    return all.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        (s.display_name ?? "").toLowerCase().includes(q) ||
        (s.description ?? "").toLowerCase().includes(q),
    );
  }, [catalog.data, search]);

  if (me.isLoading) return null;

  if (me.data?.user.role !== "admin") {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-border py-16 text-center">
        <ShieldAlertIcon className="size-5 text-muted-foreground" aria-hidden />
        <p className="text-sm text-muted-foreground">{t("catalog.adminsOnly")}</p>
      </div>
    );
  }

  const registryDisabled =
    catalog.error instanceof ApiError &&
    catalog.error.code === "registry_disabled";

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("catalog.title")}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {t("catalog.description")}
        </p>
      </div>

      <div className="flex justify-end">
        <div className="relative sm:w-72">
          <SearchIcon
            className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            className="pl-9"
            placeholder={t("install.searchPlaceholder")}
            aria-label={t("install.searchPlaceholder")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {registryDisabled ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-border px-6 py-16 text-center">
          <PackageOpenIcon className="size-5 text-muted-foreground" aria-hidden />
          <p className="text-sm font-medium">
            {t("install.registryDisabled.title")}
          </p>
          <p className="text-xs text-muted-foreground">
            {t("install.registryDisabled.description")}
          </p>
        </div>
      ) : catalog.isError ? (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-border px-6 py-16 text-center">
          <TriangleAlertIcon className="size-5 text-muted-foreground" aria-hidden />
          <p className="text-sm text-muted-foreground">
            {t("install.registryUnavailable.title")}
          </p>
          <Button variant="outline" size="sm" onClick={() => catalog.refetch()}>
            {t("install.registryUnavailable.retry")}
          </Button>
        </div>
      ) : catalog.isLoading ? (
        <CardSkeletons />
      ) : filtered.length === 0 ? (
        <p className="rounded-lg border border-border py-16 text-center text-sm text-muted-foreground">
          {search.trim() ? t("install.noResults") : t("install.emptyCatalog")}
        </p>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {filtered.map((s) => (
            <CatalogCard
              key={s.name}
              server={s}
              allowListed={allowListed.has(s.name)}
              readOnly={readOnly}
            />
          ))}
        </div>
      )}
    </div>
  );
}
