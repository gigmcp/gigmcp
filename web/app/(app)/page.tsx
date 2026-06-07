"use client";
import { useQuery } from "@tanstack/react-query";
import { useFormatter, useTranslations } from "next-intl";
import { Activity } from "lucide-react";
import { useMe, useProfiles, useServers, useCredentials, useUsers, keys } from "@/lib/queries";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { DataTable } from "@/components/data-table";
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

// Soft tinted pills per kind (Vercel style); unknown kinds fall back to a
// neutral outline pill.
const kindVariant = {
  egress: "info",
  auth: "secondary",
  admin: "outline",
} as const;

// Same gating as before: "allow" is the only non-alarming decision.
const decisionVariant = (d: string) =>
  d === "allow" ? ("success" as const) : ("destructive" as const);

export default function OverviewPage() {
  const t = useTranslations("overview");
  const format = useFormatter();
  const me = useMe();
  const profiles = useProfiles();
  const servers = useServers();
  const credentials = useCredentials();
  const isAdmin = me.data?.user.role === "admin";
  // enabled=isAdmin: skip the query for non-admins to avoid a 403 toast
  const users = useUsers(isAdmin);
  const audit = useQuery({
    queryKey: [...keys.audit, { limit: 10 }],
    queryFn: () => api.listAudit({ limit: 10 }),
  });

  const displayName = me.data?.user.display_name || me.data?.user.email || "";

  const statValue = (q: { isLoading: boolean; data?: unknown[] }) =>
    q.isLoading ? t("placeholder") : format.number(q.data?.length ?? 0);

  const auditColumns: Column<AuditEvent>[] = [
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
    {
      header: t("activity.columns.detail"),
      cell: (e) => (
        <span className="font-mono text-xs text-muted-foreground">
          {e.detail}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          {displayName ? t("welcome", { name: displayName }) : t("title")}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">{t("description")}</p>
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label={t("stats.profiles")} value={statValue(profiles)} />
        <StatCard label={t("stats.servers")} value={statValue(servers)} />
        <StatCard
          label={t("stats.credentials")}
          value={statValue(credentials)}
        />
        {isAdmin && <StatCard label={t("stats.users")} value={statValue(users)} />}
      </div>

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
            <p className="text-sm text-muted-foreground">
              {t("activity.empty")}
            </p>
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
    </div>
  );
}
