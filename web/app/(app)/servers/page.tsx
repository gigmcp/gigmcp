"use client";
import { useState } from "react";
import { toast } from "sonner";
import { useMe, useServers, useInstallServer, useUninstallServer, useReadOnly } from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { DataTable } from "@/components/data-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { Server } from "@/lib/types";
import type { Column } from "@/components/data-table";

const READ_ONLY_TITLE = "Read-only while viewing as another user";

function InstallDialog({ onSuccess, disabled }: { onSuccess: () => void; disabled?: boolean }) {
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

  const trigger = (
    <Button onClick={() => setOpen(true)} disabled={disabled}>
      Install server
    </Button>
  );

  return (
    <>
      {disabled ? (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger>
              <span tabIndex={0}>{trigger}</span>
            </TooltipTrigger>
            <TooltipContent>{READ_ONLY_TITLE}</TooltipContent>
          </Tooltip>
        </TooltipProvider>
      ) : (
        trigger
      )}
      <Dialog open={open} onOpenChange={setOpen}>
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
    </>
  );
}

export default function ServersPage() {
  const me = useMe();
  const servers = useServers();
  const uninstall = useUninstallServer();
  const readOnly = useReadOnly();
  const isAdmin = me.data?.user.role === "admin";

  const columns: Column<Server>[] = [
    { header: "ID", cell: (s) => s.id },
    { header: "Name", cell: (s) => s.name },
    ...(isAdmin
      ? [
          {
            header: "Actions",
            cell: (s: Server) => {
              const btn = (
                <Button
                  variant="destructive"
                  size="sm"
                  disabled={uninstall.isPending || readOnly}
                >
                  Uninstall
                </Button>
              );
              if (readOnly) {
                return (
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger>
                        <span tabIndex={0}>{btn}</span>
                      </TooltipTrigger>
                      <TooltipContent>{READ_ONLY_TITLE}</TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                );
              }
              return (
                <ConfirmDialog
                  trigger={btn}
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
              );
            },
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
        {isAdmin && <InstallDialog onSuccess={() => {}} disabled={readOnly} />}
      </div>

      {servers.isLoading ? (
        <div className="space-y-2">
          {[...Array(3)].map((_, i) => (
            <Skeleton key={i} className="h-10 w-full rounded-md" />
          ))}
        </div>
      ) : servers.data && servers.data.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted-foreground">
          {isAdmin
            ? "No servers installed yet. Use the Install server button to add one."
            : "No servers installed yet."}
        </p>
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
