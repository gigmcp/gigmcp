"use client";
import { useState } from "react";
import { useTranslations } from "next-intl";
import { ServerIcon } from "lucide-react";
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

/** Wraps a disabled control with the read-only impersonation tooltip. */
function ReadOnlyTooltip({ children }: { children: React.ReactNode }) {
  const t = useTranslations("servers");
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger>
          <span tabIndex={0}>{children}</span>
        </TooltipTrigger>
        <TooltipContent>{t("readOnlyTooltip")}</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

function InstallDialog({ disabled }: { disabled?: boolean }) {
  const t = useTranslations("servers");
  const [open, setOpen] = useState(false);
  const [ref, setRef] = useState("");
  const install = useInstallServer();

  function handleInstall() {
    if (!ref.trim()) return;
    install.mutate(ref.trim(), {
      onSuccess: (server) => {
        toast.success(t("install.success", { name: server.name }));
        setRef("");
        setOpen(false);
      },
      onError: (err) => {
        const msg =
          err instanceof ApiError ? err.message : t("install.error");
        toast.error(msg);
      },
    });
  }

  const trigger = (
    <Button size="sm" onClick={() => setOpen(true)} disabled={disabled}>
      {t("install.button")}
    </Button>
  );

  return (
    <>
      {disabled ? <ReadOnlyTooltip>{trigger}</ReadOnlyTooltip> : trigger}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("install.dialogTitle")}</DialogTitle>
            <DialogDescription>
              {t("install.dialogDescription")}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="ref">{t("install.refLabel")}</Label>
            <Input
              id="ref"
              className="font-mono"
              placeholder={t("install.refPlaceholder")}
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
              {install.isPending ? t("install.submitting") : t("install.submit")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

/** Column definitions for the servers table; the uninstall mutation is held
 *  here (called once per page) so its pending state stays shared across rows. */
function useServerColumns(isAdmin: boolean): Column<Server>[] {
  const t = useTranslations("servers");
  const uninstall = useUninstallServer();
  const readOnly = useReadOnly();

  const actionsColumn: Column<Server> = {
    header: t("table.actions"),
    cell: (s) => {
      const btn = (
        <Button
          variant="destructive"
          size="sm"
          disabled={uninstall.isPending || readOnly}
        >
          {t("uninstall.button")}
        </Button>
      );
      if (readOnly) {
        return <ReadOnlyTooltip>{btn}</ReadOnlyTooltip>;
      }
      return (
        <ConfirmDialog
          trigger={btn}
          title={t("uninstall.confirmTitle", { name: s.name })}
          description={t("uninstall.confirmDescription")}
          confirmLabel={t("uninstall.confirmLabel")}
          isPending={uninstall.isPending}
          onConfirm={() => {
            uninstall.mutate(s.name, {
              onSuccess: () =>
                toast.success(t("uninstall.success", { name: s.name })),
              onError: (err) => {
                const msg =
                  err instanceof ApiError
                    ? err.message
                    : t("uninstall.error");
                toast.error(msg);
              },
            });
          }}
        />
      );
    },
  };

  return [
    {
      header: t("table.id"),
      cell: (s) => (
        <span className="font-mono text-xs text-muted-foreground tabular-nums">
          {s.id}
        </span>
      ),
    },
    {
      header: t("table.name"),
      cell: (s) => <span className="font-mono">{s.name}</span>,
    },
    ...(isAdmin ? [actionsColumn] : []),
  ];
}

export default function ServersPage() {
  const t = useTranslations("servers");
  const me = useMe();
  const servers = useServers();
  const readOnly = useReadOnly();
  const isAdmin = me.data?.user.role === "admin";
  const columns = useServerColumns(isAdmin);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            {t("title")}
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {t("description")}
          </p>
        </div>
        {isAdmin && <InstallDialog disabled={readOnly} />}
      </div>

      {servers.isLoading ? (
        <div className="overflow-hidden rounded-lg border border-border">
          <div className="divide-y divide-border">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="flex h-12 items-center gap-6 px-3">
                <Skeleton className="h-4 w-10" />
                <Skeleton className="h-4 w-48" />
              </div>
            ))}
          </div>
        </div>
      ) : servers.data && servers.data.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-border py-16">
          <ServerIcon className="size-5 text-muted-foreground" aria-hidden />
          <p className="text-sm text-muted-foreground">{t("empty.title")}</p>
          {isAdmin && <InstallDialog disabled={readOnly} />}
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border">
          <DataTable
            columns={columns}
            data={servers.data ?? []}
            getKey={(s) => s.id}
          />
        </div>
      )}
    </div>
  );
}
