"use client";
import { useMemo, useState } from "react";
import { useTranslations } from "next-intl";
import { Grid3x3, PackageOpenIcon, SearchIcon } from "lucide-react";
import { useApps, useReadOnly } from "@/lib/queries";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AppCard } from "./app-card";
import { AvailableCard } from "./available-card";
import type { AppSummary } from "@/lib/types";

function matchesSearch(app: AppSummary, q: string): boolean {
  if (!q) return true;
  return (
    app.name.toLowerCase().includes(q) ||
    app.display_name.toLowerCase().includes(q) ||
    (app.category ?? "").toLowerCase().includes(q)
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

function InstalledTab({ search }: { search: string }) {
  const t = useTranslations("apps");
  const apps = useApps();

  const installed = useMemo(
    () => (apps.data ?? []).filter((a) => a.installed_by_me),
    [apps.data],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return installed.filter((a) => matchesSearch(a, q));
  }, [installed, search]);

  if (apps.isLoading) return <CardSkeletons />;

  if (installed.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-border py-16">
        <Grid3x3 className="size-5 text-muted-foreground" aria-hidden />
        <p className="text-sm text-muted-foreground">{t("empty.title")}</p>
        <p className="text-xs text-muted-foreground">{t("empty.description")}</p>
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
  const readOnly = useReadOnly();
  const apps = useApps();

  const available = useMemo(
    () => (apps.data ?? []).filter((a) => !a.installed_by_me),
    [apps.data],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return available.filter((a) => matchesSearch(a, q));
  }, [available, search]);

  if (apps.isLoading) return <CardSkeletons />;

  if (filtered.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 rounded-lg border border-border px-6 py-16 text-center">
        <PackageOpenIcon className="size-5 text-muted-foreground" aria-hidden />
        <p className="text-sm text-muted-foreground">
          {search.trim() ? t("install.noResults") : t("install.emptyCatalog")}
        </p>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {filtered.map((a) => (
        <AvailableCard key={a.name} app={a} readOnly={readOnly} />
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
