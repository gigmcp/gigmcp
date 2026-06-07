"use client";
import { useState } from "react";
import { toast } from "sonner";
import { useMe, useServers, useInstallServer, useUninstallServer } from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { DataTable } from "@/components/data-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { Server } from "@/lib/types";
import type { Column } from "@/components/data-table";

function InstallDialog({ onSuccess }: { onSuccess: () => void }) {
  const [open, setOpen] = useState(false);
  const [ref, setRef] = useState("");
  const install = useInstallServer();

  function handleInstall() {
    if (!ref.trim()) return;
    install.mutate(ref.trim(), {
      onSuccess: (server) => {
        toast.success(`Installed server "${server.name}"`);
        setRef("");
        setOpen(false);
        onSuccess();
      },
      onError: (err) => {
        const msg =
          err instanceof ApiError ? err.message : "Install failed";
        toast.error(msg);
      },
    });
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <Button onClick={() => setOpen(true)}>Install server</Button>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Install server</DialogTitle>
          <DialogDescription>
            Provide a server ref (e.g. a registry name or URL).
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <Label htmlFor="ref">Server ref</Label>
          <Input
            id="ref"
            placeholder="e.g. acme/my-server"
            value={ref}
            onChange={(e) => setRef(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleInstall();
            }}
          />
        </div>
        <DialogFooter>
          <Button
            onClick={handleInstall}
            disabled={install.isPending || !ref.trim()}
          >
            {install.isPending ? "Installing…" : "Install"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function ServersPage() {
  const me = useMe();
  const servers = useServers();
  const uninstall = useUninstallServer();
  const isAdmin = me.data?.user.role === "admin";

  const columns: Column<Server>[] = [
    { header: "ID", cell: (s) => s.id },
    { header: "Name", cell: (s) => s.name },
    ...(isAdmin
      ? [
          {
            header: "Actions",
            cell: (s: Server) => (
              <ConfirmDialog
                trigger={
                  <Button
                    variant="destructive"
                    size="sm"
                    disabled={uninstall.isPending}
                  >
                    Uninstall
                  </Button>
                }
                title={`Uninstall "${s.name}"?`}
                description="This will remove the server from all profiles that reference it."
                confirmLabel="Uninstall"
                isPending={uninstall.isPending}
                onConfirm={() => {
                  uninstall.mutate(s.name, {
                    onSuccess: () =>
                      toast.success(`Uninstalled server "${s.name}"`),
                    onError: (err) => {
                      const msg =
                        err instanceof ApiError
                          ? err.message
                          : "Uninstall failed";
                      toast.error(msg);
                    },
                  });
                }}
              />
            ),
          },
        ]
      : []),
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Servers</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Installed MCP servers available for profiles.
          </p>
        </div>
        {isAdmin && <InstallDialog onSuccess={() => {}} />}
      </div>

      {servers.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : (
        <DataTable
          columns={columns}
          data={servers.data ?? []}
          getKey={(s) => s.id}
        />
      )}
    </div>
  );
}
