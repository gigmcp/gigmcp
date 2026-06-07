"use client";
import { useQuery } from "@tanstack/react-query";
import { useMe, useProfiles, useServers, useCredentials, useUsers, keys } from "@/lib/queries";
import { api } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { DataTable } from "@/components/data-table";
import type { AuditEvent } from "@/lib/types";
import type { Column } from "@/components/data-table";

function StatCard({ title, value }: { title: string; value: number | string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-3xl font-bold">{value}</p>
      </CardContent>
    </Card>
  );
}

const kindVariant = {
  egress: "default",
  auth: "secondary",
  admin: "outline",
} as const;

const decisionVariant = (d: string) =>
  d === "allow" ? ("secondary" as const) : ("destructive" as const);

const auditColumns: Column<AuditEvent>[] = [
  {
    header: "Time",
    cell: (e) =>
      new Date(e.ts).toLocaleString(undefined, {
        dateStyle: "short",
        timeStyle: "medium",
      }),
  },
  {
    header: "Kind",
    cell: (e) => (
      <Badge variant={kindVariant[e.kind] ?? "outline"}>{e.kind}</Badge>
    ),
  },
  {
    header: "Server",
    cell: (e) => e.server || <span className="text-muted-foreground">—</span>,
  },
  {
    header: "Host",
    cell: (e) => e.host || <span className="text-muted-foreground">—</span>,
  },
  {
    header: "Decision",
    cell: (e) => (
      <Badge variant={decisionVariant(e.decision)}>{e.decision}</Badge>
    ),
  },
  {
    header: "Detail",
    cell: (e) => (
      <span className="text-muted-foreground text-xs">{e.detail}</span>
    ),
  },
];

export default function OverviewPage() {
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

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold">
          {displayName ? `Welcome, ${displayName}` : "Overview"}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Your gigmcp control plane at a glance.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard
          title="Profiles"
          value={profiles.isLoading ? "—" : (profiles.data?.length ?? 0)}
        />
        <StatCard
          title="Servers"
          value={servers.isLoading ? "—" : (servers.data?.length ?? 0)}
        />
        <StatCard
          title="Credentials"
          value={credentials.isLoading ? "—" : (credentials.data?.length ?? 0)}
        />
        {isAdmin && (
          <StatCard
            title="Users"
            value={users.isLoading ? "—" : (users.data?.length ?? 0)}
          />
        )}
      </div>

      <div>
        <h2 className="mb-4 text-lg font-semibold">Recent activity</h2>
        {audit.isLoading ? (
          <div className="space-y-2">
            {[...Array(5)].map((_, i) => (
              <Skeleton key={i} className="h-10 w-full rounded-md" />
            ))}
          </div>
        ) : audit.data?.events.length === 0 ? (
          <p className="py-8 text-center text-sm text-muted-foreground">
            No activity yet.
          </p>
        ) : (
          <DataTable
            columns={auditColumns}
            data={audit.data?.events ?? []}
            getKey={(e) => e.id}
          />
        )}
      </div>
    </div>
  );
}
