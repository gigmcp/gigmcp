"use client";
import { useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { useMe, keys } from "@/lib/queries";
import { api } from "@/lib/api";
import { DataTable } from "@/components/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { AuditEvent } from "@/lib/types";
import type { Column } from "@/components/data-table";

// NOTE: The server's GET /api/audit does not support a kind filter in v1.
// Kind filtering below is client-side, applied to the already-loaded rows.

type KindFilter = "egress" | "auth" | "admin";

function kindVariant(
  kind: string,
): "default" | "secondary" | "outline" {
  if (kind === "egress") return "default";
  if (kind === "auth") return "secondary";
  return "outline";
}

function decisionVariant(
  decision: string,
): "default" | "destructive" | "secondary" {
  const d = decision.toLowerCase();
  if (d === "resolved" || d === "allow") return "default";
  if (d === "denied" || d === "error" || d === "deny") return "destructive";
  return "secondary";
}

function formatTs(ts: string): string {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

const ALL_KINDS: KindFilter[] = ["egress", "auth", "admin"];

export default function AuditPage() {
  const me = useMe();
  const isAdmin = me.data?.user.role === "admin";
  const isImpersonating = me.data?.impersonating ?? false;

  // Admin user_id filter (only shown for non-impersonating admins)
  const [userIdFilter, setUserIdFilter] = useState("");

  // Client-side kind filter chips
  const [activeKinds, setActiveKinds] = useState<Set<KindFilter>>(
    new Set<KindFilter>(),
  );

  function toggleKind(k: KindFilter) {
    setActiveKinds((prev) => {
      const next = new Set(prev);
      if (next.has(k)) {
        next.delete(k);
      } else {
        next.add(k);
      }
      return next;
    });
  }

  const parsedUserId = userIdFilter.trim()
    ? parseInt(userIdFilter.trim(), 10) || undefined
    : undefined;

  const query = useInfiniteQuery({
    queryKey: [...keys.audit, parsedUserId],
    queryFn: ({ pageParam }) =>
      api.listAudit({
        before: pageParam as number | undefined,
        limit: 50,
        // user_id only sent by admins who are not impersonating (server ignores
        // for non-admins, but we guard here to keep the intent explicit)
        ...(isAdmin && !isImpersonating && parsedUserId
          ? { user_id: parsedUserId }
          : {}),
      }),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (lastPage) =>
      lastPage.next_before !== 0 ? lastPage.next_before : undefined,
  });

  // Flatten all pages into a single event list
  const allEvents: AuditEvent[] =
    query.data?.pages.flatMap((p) => p.events) ?? [];

  // Client-side kind filter (no server support in v1)
  const filtered =
    activeKinds.size === 0
      ? allEvents
      : allEvents.filter((e) => activeKinds.has(e.kind));

  const columns: Column<AuditEvent>[] = [
    {
      header: "Time",
      cell: (e) => (
        <span className="whitespace-nowrap text-xs text-muted-foreground">
          {formatTs(e.ts)}
        </span>
      ),
    },
    {
      header: "Kind",
      cell: (e) => (
        <Badge variant={kindVariant(e.kind)}>{e.kind}</Badge>
      ),
    },
    {
      header: "Decision",
      cell: (e) => (
        <Badge variant={decisionVariant(e.decision)}>{e.decision}</Badge>
      ),
    },
    {
      header: "Server",
      cell: (e) => (
        <span className="font-mono text-xs">{e.server || "—"}</span>
      ),
    },
    {
      header: "Host",
      cell: (e) => (
        <span className="font-mono text-xs">{e.host || "—"}</span>
      ),
    },
    {
      header: "User",
      cell: (e) => e.user_id ?? "—",
    },
    {
      header: "Profile",
      cell: (e) => e.profile_id ?? "—",
    },
    {
      header: "Detail",
      cell: (e) =>
        e.detail ? (
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger>
                <span className="block max-w-[200px] truncate text-xs cursor-default">
                  {e.detail}
                </span>
              </TooltipTrigger>
              <TooltipContent>
                <p className="max-w-sm whitespace-pre-wrap break-words">
                  {e.detail}
                </p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        ) : (
          <span className="text-muted-foreground">—</span>
        ),
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Audit log</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Event history for all MCP activity.
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-end gap-4">
        {/* Kind filter chips — client-side only (server has no kind filter in v1) */}
        <div className="space-y-1">
          <Label className="text-xs text-muted-foreground">Kind</Label>
          <div className="flex gap-2">
            {ALL_KINDS.map((k) => (
              <button
                key={k}
                type="button"
                onClick={() => toggleKind(k)}
                className={[
                  "rounded-full border px-3 py-1 text-xs font-medium transition-colors",
                  activeKinds.has(k)
                    ? "border-primary bg-primary text-primary-foreground"
                    : "border-border bg-transparent text-muted-foreground hover:border-foreground hover:text-foreground",
                ].join(" ")}
              >
                {k}
              </button>
            ))}
          </div>
        </div>

        {/* Admin user_id filter (non-impersonating admins only) */}
        {isAdmin && !isImpersonating && (
          <div className="space-y-1">
            <Label htmlFor="uid-filter" className="text-xs text-muted-foreground">
              User ID
            </Label>
            <Input
              id="uid-filter"
              type="number"
              placeholder="filter by user id"
              className="h-8 w-40 text-xs"
              value={userIdFilter}
              onChange={(e) => setUserIdFilter(e.target.value)}
            />
          </div>
        )}
      </div>

      {query.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : (
        <>
          <DataTable
            columns={columns}
            data={filtered}
            getKey={(e) => e.id}
          />

          {query.hasNextPage && (
            <div className="flex justify-center pt-2">
              <Button
                variant="outline"
                size="sm"
                disabled={query.isFetchingNextPage}
                onClick={() => query.fetchNextPage()}
              >
                {query.isFetchingNextPage ? "Loading…" : "Load more"}
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
