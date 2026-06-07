"use client";
import { useState } from "react";
import { toast } from "sonner";
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

function ImpersonateDialog({
  user,
  onClose,
}: {
  user: User;
  onClose: () => void;
}) {
  const [ttl, setTtl] = useState("30");
  const impersonate = useImpersonate();

  function handleImpersonate() {
    const ttlNum = Math.min(60, Math.max(1, parseInt(ttl, 10) || 30));
    impersonate.mutate(
      { userId: user.id, ttl: ttlNum },
      {
        onSuccess: () => {
          toast.success(`Viewing as ${user.email}`);
          onClose();
        },
        onError: (err) => {
          const msg =
            err instanceof ApiError ? err.message : "Impersonation failed";
          toast.error(msg);
        },
      },
    );
  }

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>View as {user.display_name || user.email}</DialogTitle>
          <DialogDescription>
            You will see the dashboard as this user. All mutations are blocked
            while viewing as another user.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <Label htmlFor="ttl-minutes">Duration (minutes, max 60)</Label>
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
          <Button
            onClick={handleImpersonate}
            disabled={impersonate.isPending}
          >
            {impersonate.isPending ? "Starting…" : "View as user"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function UsersPage() {
  const me = useMe();
  const role = me.data?.user.role;
  // enabled=isAdmin: skip the query until role is known, preventing a 403 toast
  // for non-admins who land here via direct URL.
  const users = useUsers(role === "admin");
  const stopImpersonation = useStopImpersonation();
  const [impersonateTarget, setImpersonateTarget] = useState<User | null>(null);

  // While me is still loading, render nothing (role unknown — don't flash content).
  if (!me.data) return null;

  // Non-admins get an empty state — nav already hides the link,
  // but a direct URL must not crash.
  if (me.data.user.role !== "admin") {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <p className="text-lg font-semibold">Admins only</p>
        <p className="mt-2 text-sm text-muted-foreground">
          You need an admin account to view this page.
        </p>
      </div>
    );
  }

  // Real user id used to hide the "Impersonate" button for self.
  // While impersonating, real_user holds the actual admin; use that id.
  const realUserId = me.data?.real_user?.id ?? me.data?.user.id;
  const isImpersonating = me.data?.impersonating ?? false;

  const columns: Column<User>[] = [
    { header: "ID", cell: (u) => u.id },
    {
      header: "Email",
      cell: (u) => u.email,
    },
    {
      header: "Display name",
      cell: (u) => u.display_name || <span className="text-muted-foreground">—</span>,
    },
    {
      header: "Role",
      cell: (u) => (
        <Badge variant={u.role === "admin" ? "default" : "secondary"}>
          {u.role}
        </Badge>
      ),
    },
    {
      header: "Actions",
      cell: (u) => {
        // Never show the impersonate button for the current real user
        if (u.id === realUserId) return null;

        if (isImpersonating) {
          // While impersonating, show "Stop viewing" — wired to the same stop mutation
          // that the banner uses
          return (
            <Button
              size="sm"
              variant="outline"
              disabled={stopImpersonation.isPending}
              onClick={() => stopImpersonation.mutate()}
            >
              {stopImpersonation.isPending ? "Stopping…" : "Stop viewing"}
            </Button>
          );
        }

        return (
          <Button
            size="sm"
            variant="outline"
            onClick={() => setImpersonateTarget(u)}
          >
            Impersonate
          </Button>
        );
      },
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Users</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          All registered users. Admin-only screen.
        </p>
      </div>

      {users.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : (
        <DataTable
          columns={columns}
          data={users.data ?? []}
          getKey={(u) => u.id}
        />
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
