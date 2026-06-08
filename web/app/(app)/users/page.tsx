"use client";
import { useState } from "react";
import { toast } from "sonner";
import { useTranslations } from "next-intl";
import { ShieldAlertIcon, UsersIcon } from "lucide-react";
import {
  useMe,
  useUsers,
  useImpersonate,
  useStopImpersonation,
} from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { DataTable } from "@/components/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { User } from "@/lib/types";
import type { Column } from "@/components/data-table";

function ImpersonateForm({
  user,
  onClose,
}: {
  user: User;
  onClose: () => void;
}) {
  const t = useTranslations("users");
  const [ttl, setTtl] = useState("30");
  const impersonate = useImpersonate();

  function handleImpersonate() {
    const ttlNum = Math.min(60, Math.max(1, parseInt(ttl, 10) || 30));
    impersonate.mutate(
      { userId: user.id, ttl: ttlNum },
      {
        onSuccess: () => {
          toast.success(t("toast.viewingAs", { email: user.email }));
          onClose();
        },
        onError: (err) => {
          const msg =
            err instanceof ApiError
              ? err.message
              : t("toast.impersonationFailed");
          toast.error(msg);
        },
      },
    );
  }

  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="ttl-minutes">{t("dialog.ttlLabel")}</Label>
        <Input
          id="ttl-minutes"
          type="number"
          min={1}
          max={60}
          value={ttl}
          onChange={(e) => setTtl(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") handleImpersonate();
          }}
        />
      </div>
      <DialogFooter>
        <Button onClick={handleImpersonate} disabled={impersonate.isPending}>
          {impersonate.isPending ? t("dialog.starting") : t("dialog.submit")}
        </Button>
      </DialogFooter>
    </>
  );
}

function ImpersonateDialog({
  user,
  onClose,
}: {
  user: User;
  onClose: () => void;
}) {
  const t = useTranslations("users");

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {t("dialog.title", { name: user.display_name || user.email })}
          </DialogTitle>
          <DialogDescription>{t("dialog.description")}</DialogDescription>
        </DialogHeader>
        <ImpersonateForm user={user} onClose={onClose} />
      </DialogContent>
    </Dialog>
  );
}

function RoleBadge({ role }: { role: User["role"] }) {
  const t = useTranslations("users");
  return (
    <Badge variant={role === "admin" ? "info" : "secondary"}>
      {role === "admin" ? t("role.admin") : t("role.user")}
    </Badge>
  );
}

function ImpersonationActions({
  user,
  realUserId,
  isImpersonating,
  stopImpersonation,
  onImpersonate,
}: {
  user: User;
  realUserId: number | undefined;
  isImpersonating: boolean;
  stopImpersonation: ReturnType<typeof useStopImpersonation>;
  onImpersonate: (user: User) => void;
}) {
  // Never show the impersonate button for the current real user
  if (user.id === realUserId) return null;

  if (isImpersonating) {
    // While impersonating, show "Stop viewing" — wired to the same stop mutation
    // that the banner uses
    return (
      <StopViewingButton stopImpersonation={stopImpersonation} />
    );
  }

  return <ImpersonateButton user={user} onImpersonate={onImpersonate} />;
}

function StopViewingButton({
  stopImpersonation,
}: {
  stopImpersonation: ReturnType<typeof useStopImpersonation>;
}) {
  const t = useTranslations("users");
  return (
    <Button
      size="sm"
      variant="outline"
      disabled={stopImpersonation.isPending}
      onClick={() => stopImpersonation.mutate()}
    >
      {stopImpersonation.isPending
        ? t("actions.stopping")
        : t("actions.stopViewing")}
    </Button>
  );
}

function ImpersonateButton({
  user,
  onImpersonate,
}: {
  user: User;
  onImpersonate: (user: User) => void;
}) {
  const t = useTranslations("users");
  return (
    <Button size="sm" variant="outline" onClick={() => onImpersonate(user)}>
      {t("actions.impersonate")}
    </Button>
  );
}

function useUserColumns({
  realUserId,
  isImpersonating,
  stopImpersonation,
  onImpersonate,
}: {
  realUserId: number | undefined;
  isImpersonating: boolean;
  stopImpersonation: ReturnType<typeof useStopImpersonation>;
  onImpersonate: (user: User) => void;
}): Column<User>[] {
  const t = useTranslations("users");

  return [
    {
      header: t("table.id"),
      cell: (u) => (
        <span className="font-mono tabular-nums text-muted-foreground">
          {u.id}
        </span>
      ),
    },
    {
      header: t("table.email"),
      cell: (u) => u.email,
    },
    {
      header: t("table.displayName"),
      cell: (u) =>
        u.display_name || (
          <span className="text-muted-foreground">{t("table.noValue")}</span>
        ),
    },
    {
      header: t("table.role"),
      cell: (u) => <RoleBadge role={u.role} />,
    },
    {
      header: t("table.actions"),
      cell: (u) => (
        <ImpersonationActions
          user={u}
          realUserId={realUserId}
          isImpersonating={isImpersonating}
          stopImpersonation={stopImpersonation}
          onImpersonate={onImpersonate}
        />
      ),
    },
  ];
}

function AdminOnlyNotice() {
  const t = useTranslations("users");
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-border py-24 text-center">
      <ShieldAlertIcon
        className="size-8 text-muted-foreground"
        aria-hidden="true"
      />
      <p className="mt-4 text-base font-semibold">{t("adminOnly.title")}</p>
      <p className="mt-1 text-sm text-muted-foreground">
        {t("adminOnly.description")}
      </p>
    </div>
  );
}

function UsersTableSkeleton() {
  return (
    <div className="overflow-hidden rounded-lg border border-border">
      <div className="border-b border-border px-3 py-3">
        <Skeleton className="h-4 w-48" />
      </div>
      {[...Array(4)].map((_, i) => (
        <div
          key={i}
          className="flex h-12 items-center border-b border-border px-3 last:border-0"
        >
          <Skeleton className="h-4 w-full" />
        </div>
      ))}
    </div>
  );
}

function UsersEmptyState() {
  const t = useTranslations("users");
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-border py-16 text-center">
      <UsersIcon className="size-8 text-muted-foreground" aria-hidden="true" />
      <p className="mt-4 text-sm text-muted-foreground">{t("empty")}</p>
    </div>
  );
}

export default function UsersPage() {
  const t = useTranslations("users");
  const me = useMe();
  const role = me.data?.user.role;
  // enabled=isAdmin: skip the query until role is known, preventing a 403 toast
  // for non-admins who land here via direct URL.
  const users = useUsers(role === "admin");
  // Single mutation instance shared by all rows so isPending disables every
  // "Stop viewing" button at once.
  const stopImpersonation = useStopImpersonation();
  const [impersonateTarget, setImpersonateTarget] = useState<User | null>(null);

  // Real user id used to hide the "Impersonate" button for self.
  // While impersonating, real_user holds the actual admin; use that id.
  const realUserId = me.data?.real_user?.id ?? me.data?.user.id;
  const isImpersonating = me.data?.impersonating ?? false;

  const columns = useUserColumns({
    realUserId,
    isImpersonating,
    stopImpersonation,
    onImpersonate: setImpersonateTarget,
  });

  // While me is still loading, render nothing (role unknown — don't flash content).
  if (!me.data) return null;

  // Non-admins get an empty state — nav already hides the link,
  // but a direct URL must not crash.
  if (me.data.user.role !== "admin") {
    return <AdminOnlyNotice />;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{t("title")}</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {t("description")}
        </p>
      </div>

      {users.isLoading ? (
        <UsersTableSkeleton />
      ) : users.data && users.data.length === 0 ? (
        <UsersEmptyState />
      ) : (
        <div className="overflow-hidden rounded-lg border border-border">
          <DataTable
            columns={columns}
            data={users.data ?? []}
            getKey={(u) => u.id}
          />
        </div>
      )}

      {impersonateTarget && (
        <ImpersonateDialog
          user={impersonateTarget}
          onClose={() => setImpersonateTarget(null)}
        />
      )}
    </div>
  );
}
