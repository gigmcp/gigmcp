"use client";
import { useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { useFormatter, useTranslations } from "next-intl";
import { ScrollText } from "lucide-react";
import { useMe, keys } from "@/lib/queries";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { DataTable } from "@/components/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { AuditEvent } from "@/lib/types";
import type { Column } from "@/components/data-table";

// NOTE: The server's GET /api/audit does not support a kind filter.
// Kind filtering below is client-side, applied to the already-loaded rows.

type KindFilter = "egress" | "auth" | "admin";

const ALL_KINDS: KindFilter[] = ["egress", "auth", "admin"];

function kindVariant(kind: string): "info" | "secondary" | "outline" {
  if (kind === "egress") return "info";
  if (kind === "auth") return "secondary";
  return "outline";
}

function decisionVariant(
  decision: string,
): "success" | "destructive" | "secondary" {
  const d = decision.toLowerCase();
  if (d === "resolved" || d === "allow") return "success";
  if (d === "denied" || d === "error" || d === "deny") return "destructive";
  return "secondary";
}

// Kind/decision values come from server data; translate the known ones and
// fall back to the raw value for anything unexpected.
function useAuditLabels() {
  const t = useTranslations("audit");

  function kindLabel(kind: string): string {
    return t.has(`kinds.${kind}`) ? t(`kinds.${kind}`) : kind;
  }

  function decisionLabel(decision: string): string {
    const key = `decisions.${decision.toLowerCase()}`;
    return t.has(key) ? t(key) : decision;
  }

  return { kindLabel, decisionLabel };
}

function KindBadge({ kind }: { kind: string }) {
  const { kindLabel } = useAuditLabels();
  return <Badge variant={kindVariant(kind)}>{kindLabel(kind)}</Badge>;
}

function DecisionBadge({ decision }: { decision: string }) {
  const { decisionLabel } = useAuditLabels();
  return (
    <Badge variant={decisionVariant(decision)}>{decisionLabel(decision)}</Badge>
  );
}

function useAuditColumns(): Column<AuditEvent>[] {
  const t = useTranslations("audit");
  const format = useFormatter();

  function formatTs(ts: string): string {
    try {
      return format.dateTime(new Date(ts), {
        dateStyle: "medium",
        timeStyle: "medium",
      });
    } catch {
      return ts;
    }
  }

  return [
    {
      header: t("columns.time"),
      cell: (e) => (
        <span className="font-mono text-xs whitespace-nowrap text-muted-foreground tabular-nums">
          {formatTs(e.ts)}
        </span>
      ),
    },
    {
      header: t("columns.kind"),
      cell: (e) => <KindBadge kind={e.kind} />,
    },
    {
      header: t("columns.decision"),
      cell: (e) => <DecisionBadge decision={e.decision} />,
    },
    {
      header: t("columns.server"),
      cell: (e) => (
        <span className="font-mono text-xs">{e.server || t("noValue")}</span>
      ),
    },
    {
      header: t("columns.host"),
      cell: (e) => (
        <span className="font-mono text-xs">{e.host || t("noValue")}</span>
      ),
    },
    {
      header: t("columns.user"),
      cell: (e) =>
        e.user_id != null ? (
          <span className="font-mono text-xs tabular-nums">{e.user_id}</span>
        ) : (
          <span className="text-muted-foreground">{t("noValue")}</span>
        ),
    },
    {
      header: t("columns.profile"),
      cell: (e) =>
        e.profile_id != null ? (
          <span className="font-mono text-xs tabular-nums">
            {e.profile_id}
          </span>
        ) : (
          <span className="text-muted-foreground">{t("noValue")}</span>
        ),
    },
    {
      header: t("columns.detail"),
      cell: (e) =>
        e.detail ? (
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger>
                <span className="block max-w-[200px] cursor-default truncate font-mono text-xs">
                  {e.detail}
                </span>
              </TooltipTrigger>
              <TooltipContent>
                <p className="max-w-sm font-mono break-words whitespace-pre-wrap">
                  {e.detail}
                </p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        ) : (
          <span className="text-muted-foreground">{t("noValue")}</span>
        ),
    },
  ];
}

// Kind filter chips — client-side only (server has no kind filter)
function KindFilterChips({
  activeKinds,
  onToggle,
}: {
  activeKinds: Set<KindFilter>;
  onToggle: (k: KindFilter) => void;
}) {
  const t = useTranslations("audit");
  const { kindLabel } = useAuditLabels();
  return (
    <div className="space-y-1.5">
      <Label className="text-xs text-muted-foreground">
        {t("filters.kind")}
      </Label>
      <div className="flex gap-2">
        {ALL_KINDS.map((k) => (
          <button
            key={k}
            type="button"
            aria-pressed={activeKinds.has(k)}
            onClick={() => onToggle(k)}
            className={cn(
              "rounded-full border px-3 py-1 text-xs font-medium transition-colors duration-150 ease-out outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/30",
              activeKinds.has(k)
                ? "border-primary bg-primary text-primary-foreground hover:bg-primary/90"
                : "border-border bg-background text-muted-foreground hover:bg-muted hover:text-foreground",
            )}
          >
            {kindLabel(k)}
          </button>
        ))}
      </div>
    </div>
  );
}

function AuditTableSkeleton() {
  return (
    <div className="overflow-hidden rounded-lg border border-border">
      <div className="divide-y divide-border">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="flex h-12 items-center px-3">
            <Skeleton className="h-4 w-full" />
          </div>
        ))}
      </div>
    </div>
  );
}

function AuditEmptyState() {
  const t = useTranslations("audit");
  return (
    <div className="flex flex-col items-center justify-center gap-1.5 rounded-lg border border-border py-16 text-center">
      <ScrollText
        className="mb-1 size-6 text-muted-foreground"
        aria-hidden="true"
      />
      <p className="text-sm font-medium">{t("empty.title")}</p>
      <p className="text-sm text-muted-foreground">{t("empty.description")}</p>
    </div>
  );
}

function LoadMoreFooter({
  hasNextPage,
  isFetchingNextPage,
  onLoadMore,
}: {
  hasNextPage: boolean;
  isFetchingNextPage: boolean;
  onLoadMore: () => void;
}) {
  const t = useTranslations("audit");
  return hasNextPage ? (
    <div className="flex justify-center pt-2">
      <Button
        variant="outline"
        size="sm"
        disabled={isFetchingNextPage}
        onClick={() => onLoadMore()}
      >
        {isFetchingNextPage ? t("loadingMore") : t("loadMore")}
      </Button>
    </div>
  ) : (
    <p className="pt-2 text-center text-xs text-muted-foreground">
      {t("endOfList")}
    </p>
  );
}

export default function AuditPage() {
  const t = useTranslations("audit");
  const me = useMe();
  const isAdmin = me.data?.user.role === "admin";
  const isImpersonating = me.data?.impersonating ?? false;
  const columns = useAuditColumns();

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

  // Client-side kind filter (no server-side support)
  const filtered =
    activeKinds.size === 0
      ? allEvents
      : allEvents.filter((e) => activeKinds.has(e.kind));

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{t("title")}</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {t("description")}
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-end gap-4">
        <KindFilterChips activeKinds={activeKinds} onToggle={toggleKind} />

        {/* Admin user_id filter (non-impersonating admins only) */}
        {isAdmin && !isImpersonating && (
          <div className="space-y-1.5">
            <Label
              htmlFor="uid-filter"
              className="text-xs text-muted-foreground"
            >
              {t("filters.userId")}
            </Label>
            <Input
              id="uid-filter"
              type="number"
              placeholder={t("filters.userIdPlaceholder")}
              className="h-8 w-44 text-xs"
              value={userIdFilter}
              onChange={(e) => setUserIdFilter(e.target.value)}
            />
          </div>
        )}
      </div>

      {query.isLoading ? (
        <AuditTableSkeleton />
      ) : filtered.length === 0 ? (
        <AuditEmptyState />
      ) : (
        <>
          <div className="overflow-hidden rounded-lg border border-border">
            <DataTable columns={columns} data={filtered} getKey={(e) => e.id} />
          </div>

          <LoadMoreFooter
            hasNextPage={query.hasNextPage}
            isFetchingNextPage={query.isFetchingNextPage}
            onLoadMore={() => query.fetchNextPage()}
          />
        </>
      )}
    </div>
  );
}
