"use client";
import { useState } from "react";
import Link from "next/link";
import { useFormatter, useTranslations } from "next-intl";
import { Layers } from "lucide-react";
import { useProfiles, useReadOnly } from "@/lib/queries";
import { DataTable } from "@/components/data-table";
import { TokenRevealDialog } from "@/components/token-reveal-dialog";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import type { Profile } from "@/lib/types";
import type { Column } from "@/components/data-table";
import {
  CreateProfileDialog,
  CreateProfileTrigger,
} from "./create-profile-dialog";

function useProfileColumns(): Column<Profile>[] {
  const t = useTranslations("profiles");
  const format = useFormatter();

  return [
    {
      header: t("list.columns.name"),
      cell: (p) => (
        <Link
          href={`/profiles/${p.id}`}
          className="font-medium underline-offset-4 hover:underline"
        >
          {p.name}
        </Link>
      ),
    },
    {
      header: t("list.columns.slug"),
      cell: (p) => <span className="font-mono text-xs">{p.slug}</span>,
    },
    {
      header: t("list.columns.endpoint"),
      cell: (p) => (
        <span className="font-mono text-xs text-muted-foreground">
          {p.endpoint}
        </span>
      ),
    },
    {
      header: t("list.columns.servers"),
      cell: (p) => (
        <span className="tabular-nums">{format.number(p.servers.length)}</span>
      ),
    },
  ];
}

function ProfilesPageHeader({
  readOnly,
  onCreate,
}: {
  readOnly: boolean;
  onCreate: () => void;
}) {
  const t = useTranslations("profiles");

  return (
    <div className="flex items-start justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("list.title")}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {t("list.description")}
        </p>
      </div>
      <CreateProfileTrigger disabled={readOnly} onClick={onCreate} />
    </div>
  );
}

function ProfilesTableSkeleton() {
  return (
    <div className="overflow-hidden rounded-lg border border-border">
      <div className="divide-y divide-border">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="flex h-12 items-center px-3">
            <Skeleton className="h-4 w-full" />
          </div>
        ))}
      </div>
    </div>
  );
}

function ProfilesEmptyState({
  readOnly,
  onCreate,
}: {
  readOnly: boolean;
  onCreate: () => void;
}) {
  const t = useTranslations("profiles");

  return (
    <div className="flex flex-col items-center justify-center gap-4 rounded-lg border border-border px-6 py-16 text-center">
      <Layers className="size-8 text-muted-foreground" aria-hidden="true" />
      <div className="space-y-1">
        <p className="text-sm font-medium">{t("list.empty.title")}</p>
        <p className="text-sm text-muted-foreground">
          {t("list.empty.description")}
        </p>
      </div>
      <Button disabled={readOnly} onClick={onCreate}>
        {t("create.trigger")}
      </Button>
    </div>
  );
}

export default function ProfilesPage() {
  const profiles = useProfiles();
  const readOnly = useReadOnly();
  const [createOpen, setCreateOpen] = useState(false);
  const [revealToken, setRevealToken] = useState<string | null>(null);
  const columns = useProfileColumns();

  return (
    <div className="space-y-6">
      <ProfilesPageHeader
        readOnly={readOnly}
        onCreate={() => setCreateOpen(true)}
      />

      {profiles.isLoading ? (
        <ProfilesTableSkeleton />
      ) : profiles.data && profiles.data.length === 0 ? (
        <ProfilesEmptyState
          readOnly={readOnly}
          onCreate={() => setCreateOpen(true)}
        />
      ) : (
        <div className="overflow-hidden rounded-lg border border-border">
          <DataTable
            columns={columns}
            data={profiles.data ?? []}
            getKey={(p) => p.id}
          />
        </div>
      )}

      {/* Both dialogs stay mounted unconditionally at the page root so they
          survive profiles-query invalidations (one-time token reveal flow). */}
      <CreateProfileDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onReveal={setRevealToken}
      />

      <TokenRevealDialog
        open={!!revealToken}
        token={revealToken ?? ""}
        onClose={() => setRevealToken(null)}
      />
    </div>
  );
}
