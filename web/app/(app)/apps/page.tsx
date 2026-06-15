"use client";
import { useMemo, useState } from "react";
import Link from "next/link";
import { useTranslations } from "next-intl";
import { Grid3x3, PackageOpenIcon, SearchIcon, TriangleAlertIcon } from "lucide-react";
import { toast } from "sonner";
import {
  useApps,
  useCatalog,
  useInstallServer,
  useMe,
  useReadOnly,
} from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";
import { monogram, monogramColor } from "@/lib/monogram";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AppCard } from "./app-card";
import type { CatalogServer } from "@/lib/types";

function CatalogCard({
  server,
  installed,
  isAdmin,
  readOnly,
}: {
  server: CatalogServer;
  installed: boolean;
  isAdmin: boolean;
  readOnly: boolean;
}) {
  const t = useTranslations("apps");
  const install = useInstallServer();

  function doInstall() {
    install.mutate(server.name, {
      onSuccess: (s) => toast.success(t("install.success", { name: s.name })),
      onError: (err) =>
        toast.error(err instanceof ApiError ? err.message : t("install.error")),
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
            {installed && (
              <Badge variant="success">{t("install.installedBadge")}</Badge>
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
        {installed ? (
          <Link
            href={`/apps/${server.name}`}
            className="text-xs font-medium text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
          >
            {t("action.manage")}
          </Link>
        ) : isAdmin ? (
          <Button
            size="xs"
            onClick={doInstall}
            disabled={readOnly || install.isPending}
          >
            {install.isPending ? t("install.submitting") : t("install.button")}
          </Button>
        ) : null}
      </div>
    </div>
  );
}

function InstalledTab({ search }: { search: string }) {
  const t = useTranslations("apps");
  const apps = useApps();

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const all = apps.data ?? [];
    if (!q) return all;
    return all.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        a.display_name.toLowerCase().includes(q) ||
        (a.category ?? "").toLowerCase().includes(q),
    );
  }, [apps.data, search]);

  if (apps.isLoading) {
    return (
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {[...Array(6)].map((_, i) => (
          <Skeleton key={i} className="h-32 rounded-xl" />
        ))}
      </div>
    );
  }

  if ((apps.data ?? []).length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-border py-16">
        <Grid3x3 className="size-5 text-muted-foreground" aria-hidden />
        <p className="text-sm text-muted-foreground">{t("empty.title")}</p>
      </div>
    );
  }

  if (filtered.length === 0) {
    return (
      <p className="rounded-lg border border-border py-16 text-center text-sm text-muted-foreground">
        {t("install.noResults")}
      </p>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {filtered.map((a) => (
        <AppCard key={a.name} app={a} />
      ))}
    </div>
  );
}

function AvailableTab({ search }: { search: string }) {
  const t = useTranslations("apps");
  const me = useMe();
  const readOnly = useReadOnly();
  const isAdmin = me.data?.user.role === "admin";
  const catalog = useCatalog();
  const apps = useApps();

  const installedNames = useMemo(
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

  const registryDisabled =
    catalog.error instanceof ApiError &&
    catalog.error.code === "registry_disabled";

  if (registryDisabled) {
    return (
      <div className="flex flex-col items-center gap-2 rounded-lg border border-border px-6 py-16 text-center">
        <PackageOpenIcon className="size-5 text-muted-foreground" aria-hidden />
        <p className="text-sm font-medium">{t("install.registryDisabled.title")}</p>
        <p className="text-xs text-muted-foreground">
          {t("install.registryDisabled.description")}
        </p>
      </div>
    );
  }

  if (catalog.isError) {
    return (
      <div className="flex flex-col items-center gap-3 rounded-lg border border-border px-6 py-16 text-center">
        <TriangleAlertIcon className="size-5 text-muted-foreground" aria-hidden />
        <p className="text-sm text-muted-foreground">
          {t("install.registryUnavailable.title")}
        </p>
        <Button variant="outline" size="sm" onClick={() => catalog.refetch()}>
          {t("install.registryUnavailable.retry")}
        </Button>
      </div>
    );
  }

  if (catalog.isLoading) {
    return (
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {[...Array(6)].map((_, i) => (
          <Skeleton key={i} className="h-32 rounded-xl" />
        ))}
      </div>
    );
  }

  if (filtered.length === 0) {
    return (
      <p className="rounded-lg border border-border py-16 text-center text-sm text-muted-foreground">
        {search.trim() ? t("install.noResults") : t("install.emptyCatalog")}
      </p>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {filtered.map((s) => (
        <CatalogCard
          key={s.name}
          server={s}
          installed={installedNames.has(s.name)}
          isAdmin={isAdmin}
          readOnly={readOnly}
        />
      ))}
    </div>
  );
}

export default function AppsPage() {
  const t = useTranslations("apps");
  const [search, setSearch] = useState("");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{t("title")}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t("description")}</p>
      </div>

      <Tabs defaultValue="available">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <TabsList>
            <TabsTrigger value="available">{t("tabs.available")}</TabsTrigger>
            <TabsTrigger value="installed">{t("tabs.installed")}</TabsTrigger>
          </TabsList>
          <div className="relative sm:w-72">
            <SearchIcon
              className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden
            />
            <Input
              className="pl-9"
              placeholder={t("searchPlaceholder")}
              aria-label={t("searchPlaceholder")}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>

        <TabsContent value="available" className="mt-2">
          <AvailableTab search={search} />
        </TabsContent>
        <TabsContent value="installed" className={cn("mt-2")}>
          <InstalledTab search={search} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
