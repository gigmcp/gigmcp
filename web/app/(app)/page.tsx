"use client";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useFormatter, useTranslations } from "next-intl";
import { Activity } from "lucide-react";
import { useMe, useOverview, useApps, keys } from "@/lib/queries";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { DataTable } from "@/components/data-table";
import { ActivityHeatmap } from "@/components/activity-heatmap";
import { monogram, monogramColor } from "@/lib/monogram";
import type { AuditEvent } from "@/lib/types";
import type { Column } from "@/components/data-table";

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <Card>
      <CardContent>
        <p className="text-sm text-muted-foreground">{label}</p>
        <p className="mt-2 text-3xl font-semibold tracking-tight tabular-nums">
          {value}
        </p>
      </CardContent>
    </Card>
  );
}

const kindVariant = {
  egress: "info",
  auth: "secondary",
  admin: "outline",
} as const;

const decisionVariant = (d: string) =>
  d === "allow" || d === "resolved"
    ? ("success" as const)
    : ("destructive" as const);

function useAuditColumns(): Column<AuditEvent>[] {
  const t = useTranslations("overview");
  const format = useFormatter();
  return [
    {
      header: t("activity.columns.time"),
      cell: (e) => (
        <span className="font-mono text-xs text-muted-foreground tabular-nums">
          {format.dateTime(new Date(e.ts), {
            dateStyle: "short",
            timeStyle: "medium",
          })}
        </span>
      ),
    },
    {
      header: t("activity.columns.kind"),
      cell: (e) => (
        <Badge variant={kindVariant[e.kind] ?? "outline"}>
          {t.has(`kinds.${e.kind}`) ? t(`kinds.${e.kind}`) : e.kind}
        </Badge>
      ),
    },
    {
      header: t("activity.columns.server"),
      cell: (e) =>
        e.server ? (
          <span className="font-mono text-xs">{e.server}</span>
        ) : (
          <span className="text-muted-foreground">{t("placeholder")}</span>
        ),
    },
    {
      header: t("activity.columns.host"),
      cell: (e) =>
        e.host ? (
          <span className="font-mono text-xs">{e.host}</span>
        ) : (
          <span className="text-muted-foreground">{t("placeholder")}</span>
        ),
    },
    {
      header: t("activity.columns.decision"),
      cell: (e) => (
        <Badge variant={decisionVariant(e.decision)}>
          {t.has(`decisions.${e.decision}`)
            ? t(`decisions.${e.decision}`)
            : e.decision}
        </Badge>
      ),
    },
  ];
}

export default function OverviewPage() {
  const t = useTranslations("overview");
  const format = useFormatter();
  const me = useMe();
  const overview = useOverview();
  const apps = useApps();
  const audit = useQuery({
    queryKey: [...keys.audit, { limit: 10 }],
    queryFn: () => api.listAudit({ limit: 10 }),
  });
  const auditColumns = useAuditColumns();

  const displayName = me.data?.user.display_name || me.data?.user.email || "";
  const stat = (n?: number) =>
    overview.isLoading || n === undefined ? t("placeholder") : format.number(n);

  // Suggested = installed apps the user has not yet connected (first 4).
  const suggested = (apps.data ?? [])
    .filter((a) => !a.connected && a.auth_type !== "none")
    .slice(0, 4);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          {displayName ? t("welcome", { name: displayName }) : t("title")}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">{t("description")}</p>
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label={t("stats.toolCalls")} value={stat(overview.data?.tool_calls)} />
        <StatCard label={t("stats.apps")} value={stat(overview.data?.apps)} />
        <StatCard label={t("stats.connected")} value={stat(overview.data?.connected)} />
        <StatCard label={t("stats.profiles")} value={stat(overview.data?.profiles)} />
      </div>

      {overview.isLoading ? (
        <Skeleton className="h-28 w-full rounded-lg" />
      ) : (
        <ActivityHeatmap days={overview.data?.heatmap ?? []} />
      )}

      <div className="grid gap-8 lg:grid-cols-2">
        <div>
          <h2 className="mb-4 text-base font-semibold tracking-tight">
            {t("activity.title")}
          </h2>
          {audit.isLoading ? (
            <div className="space-y-3 rounded-lg border border-border p-4">
              {[...Array(5)].map((_, i) => (
                <Skeleton key={i} className="h-8 w-full rounded-md" />
              ))}
            </div>
          ) : audit.data?.events.length === 0 ? (
            <div className="flex flex-col items-center gap-2 rounded-lg border border-border py-12">
              <Activity className="size-5 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">{t("activity.empty")}</p>
            </div>
          ) : (
            <div className="overflow-hidden rounded-lg border border-border">
              <DataTable
                columns={auditColumns}
                data={audit.data?.events ?? []}
                getKey={(e) => e.id}
              />
            </div>
          )}
        </div>

        <div>
          <h2 className="mb-4 text-base font-semibold tracking-tight">
            {t("suggested.title")}
          </h2>
          {apps.isLoading ? (
            <div className="space-y-3">
              {[...Array(3)].map((_, i) => (
                <Skeleton key={i} className="h-14 w-full rounded-lg" />
              ))}
            </div>
          ) : suggested.length === 0 ? (
            <div className="rounded-lg border border-border py-12 text-center text-sm text-muted-foreground">
              {t("suggested.empty")}
            </div>
          ) : (
            <ul className="space-y-2">
              {suggested.map((a) => (
                <li key={a.name}>
                  <Link
                    href={`/apps/${a.name}`}
                    className="flex items-center gap-3 rounded-lg border border-border p-3 transition-colors hover:bg-accent"
                  >
                    <span
                      className="flex size-9 shrink-0 items-center justify-center rounded-md text-xs font-semibold text-white"
                      style={{ backgroundColor: monogramColor(a.name) }}
                    >
                      {monogram(a.name)}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">
                        {a.display_name}
                      </span>
                      <span className="block truncate text-xs text-muted-foreground">
                        {t(`authType.${a.auth_type}`)}
                      </span>
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
