"use client";
import { useState, type ReactNode } from "react";
import { toast } from "sonner";
import { useTranslations } from "next-intl";
import { ChevronDownIcon, ChevronRightIcon, KeyRoundIcon } from "lucide-react";
import { useCredentials, usePutCredential, useDeleteCredential, useReadOnly } from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { DataTable } from "@/components/data-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
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
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import type { Credential, CredentialPutBody } from "@/lib/types";
import type { Column } from "@/components/data-table";

/* Validation patterns shown as hints — technical literals, interpolated into
   the translated hint messages so they are never themselves translated. */
const SERVER_PATTERN = "^[a-z0-9][a-z0-9_-]{0,63}$";
const HEADER_PATTERN = "^[A-Za-z0-9-]+$";
const HOST_PATTERN = "^(\\*\\.)?[a-z0-9.-]+$";

/* Geist-style textarea matching ui/input.tsx (mono — secrets and host lists). */
const textareaClass =
  "min-h-20 w-full min-w-0 resize-none rounded-md border border-input bg-background px-3 py-2 font-mono text-sm text-foreground transition-colors duration-150 ease-out outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/30 disabled:pointer-events-none disabled:cursor-not-allowed disabled:bg-muted disabled:opacity-50";

const codeTag = {
  code: (chunks: ReactNode) => <span className="font-mono">{chunks}</span>,
};

interface CredentialDialogProps {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  prefillServer?: string;
}

function CredentialDialog({
  open,
  onOpenChange,
  prefillServer,
}: CredentialDialogProps) {
  const t = useTranslations("credentials");
  const [server, setServer] = useState(prefillServer ?? "");
  const [secret, setSecret] = useState("");
  const [injectHeader, setInjectHeader] = useState("");
  const [injectFormat, setInjectFormat] = useState("");
  const [placeholder, setPlaceholder] = useState("");
  const [allowedHosts, setAllowedHosts] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const put = usePutCredential();

  function reset() {
    setServer(prefillServer ?? "");
    setSecret("");
    setInjectHeader("");
    setInjectFormat("");
    setPlaceholder("");
    setAllowedHosts("");
    setShowAdvanced(false);
    setError(null);
  }

  function handleOpenChange(o: boolean) {
    if (!o) reset();
    onOpenChange(o);
  }

  function handleSubmit() {
    if (!server.trim() || !secret) return;
    setError(null);

    const body: CredentialPutBody = { secret };
    if (injectHeader.trim()) body.inject_header = injectHeader.trim();
    if (injectFormat.trim()) body.inject_format = injectFormat.trim();
    if (placeholder.trim()) body.placeholder = placeholder.trim();
    if (allowedHosts.trim()) {
      body.allowed_hosts = allowedHosts
        .split(/[\n,]+/)
        .map((h) => h.trim())
        .filter(Boolean);
    }

    put.mutate(
      { server: server.trim(), body },
      {
        onSuccess: () => {
          toast.success(t("toast.saved", { server: server.trim() }));
          handleOpenChange(false);
        },
        onError: (err) => {
          if (err instanceof ApiError) {
            setError(err.message);
          } else {
            setError(t("errors.saveFailed"));
          }
        },
      },
    );
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            {prefillServer
              ? t("dialog.updateTitle", { server: prefillServer })
              : t("dialog.addTitle")}
          </DialogTitle>
          <DialogDescription>{t("dialog.description")}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="cred-server">{t("form.server.label")}</Label>
            <Input
              id="cred-server"
              placeholder={t("form.server.placeholder")}
              value={server}
              onChange={(e) => setServer(e.target.value)}
              disabled={!!prefillServer}
              className="font-mono"
            />
            <p className="text-xs text-muted-foreground">
              {t.rich("form.server.hint", { ...codeTag, pattern: SERVER_PATTERN })}
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="cred-secret">{t("form.secret.label")}</Label>
            <textarea
              id="cred-secret"
              className={textareaClass}
              placeholder={t("form.secret.placeholder")}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </div>

          <div>
            <button
              type="button"
              onClick={() => setShowAdvanced((v) => !v)}
              className="flex items-center gap-1 text-xs text-muted-foreground transition-colors duration-150 ease-out hover:text-foreground"
            >
              {showAdvanced ? (
                <ChevronDownIcon className="size-3.5" aria-hidden="true" />
              ) : (
                <ChevronRightIcon className="size-3.5" aria-hidden="true" />
              )}
              {t("form.advanced.toggle")}
            </button>

            {showAdvanced && (
              <div className="mt-3 space-y-4">
                <Separator />
                <p className="text-xs text-muted-foreground">
                  {t("form.advanced.note")}
                </p>

                <div className="space-y-2">
                  <Label htmlFor="cred-inject-header">
                    {t("form.injectHeader.label")}
                  </Label>
                  <Input
                    id="cred-inject-header"
                    placeholder={t("form.injectHeader.placeholder")}
                    value={injectHeader}
                    onChange={(e) => setInjectHeader(e.target.value)}
                    className="font-mono"
                  />
                  <p className="text-xs text-muted-foreground">
                    {t.rich("form.injectHeader.hint", {
                      ...codeTag,
                      pattern: HEADER_PATTERN,
                    })}
                  </p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="cred-inject-format">
                    {t("form.injectFormat.label")}
                  </Label>
                  <Input
                    id="cred-inject-format"
                    placeholder={t("form.injectFormat.placeholder")}
                    value={injectFormat}
                    onChange={(e) => setInjectFormat(e.target.value)}
                    className="font-mono"
                  />
                  <p className="text-xs text-muted-foreground">
                    {t.rich("form.injectFormat.hint", codeTag)}
                  </p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="cred-placeholder">
                    {t("form.placeholder.label")}
                  </Label>
                  <Input
                    id="cred-placeholder"
                    placeholder={t("form.placeholder.placeholder")}
                    value={placeholder}
                    onChange={(e) => setPlaceholder(e.target.value)}
                    className="font-mono"
                  />
                  <p className="text-xs text-muted-foreground">
                    {t("form.placeholder.hint")}
                  </p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="cred-allowed-hosts">
                    {t("form.allowedHosts.label")}
                  </Label>
                  <textarea
                    id="cred-allowed-hosts"
                    className={textareaClass}
                    placeholder={t("form.allowedHosts.placeholder")}
                    value={allowedHosts}
                    onChange={(e) => setAllowedHosts(e.target.value)}
                    spellCheck={false}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t.rich("form.allowedHosts.hint", {
                      ...codeTag,
                      pattern: HOST_PATTERN,
                    })}
                  </p>
                </div>
              </div>
            )}
          </div>

          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>

        <DialogFooter>
          <Button
            onClick={handleSubmit}
            disabled={put.isPending || !server.trim() || !secret}
          >
            {put.isPending ? t("dialog.saving") : t("dialog.save")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** Primary action, disabled with an explanatory tooltip while impersonating. */
function AddCredentialButton({
  readOnly,
  onClick,
}: {
  readOnly: boolean;
  onClick: () => void;
}) {
  const t = useTranslations("credentials");
  if (readOnly) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger>
            <span tabIndex={0}>
              <Button disabled>{t("add")}</Button>
            </span>
          </TooltipTrigger>
          <TooltipContent>{t("readOnlyTooltip")}</TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }
  return <Button onClick={onClick}>{t("add")}</Button>;
}

export default function CredentialsPage() {
  const t = useTranslations("credentials");
  const credentials = useCredentials();
  const deleteCredential = useDeleteCredential();
  const readOnly = useReadOnly();
  const [addOpen, setAddOpen] = useState(false);
  const [editServer, setEditServer] = useState<string | null>(null);

  const columns: Column<Credential>[] = [
    {
      header: t("table.server"),
      cell: (c) => <span className="font-mono">{c.server}</span>,
    },
    {
      header: t("table.injectHeader"),
      cell: (c) =>
        c.inject_header ? (
          <span className="font-mono text-xs">{c.inject_header}</span>
        ) : (
          <span className="text-muted-foreground">{t("table.none")}</span>
        ),
    },
    {
      header: t("table.allowedHosts"),
      cell: (c) =>
        c.allowed_hosts.length > 0 ? (
          <span className="tabular-nums">
            {t("table.hostCount", { count: c.allowed_hosts.length })}
          </span>
        ) : (
          <span className="text-muted-foreground">{t("table.none")}</span>
        ),
    },
    {
      header: t("table.actions"),
      cell: (c) => {
        const updateBtn = (
          <Button
            variant="outline"
            size="sm"
            disabled={readOnly}
            onClick={() => !readOnly && setEditServer(c.server)}
          >
            {t("actions.update")}
          </Button>
        );
        const deleteBtn = (
          <Button
            variant="destructive"
            size="sm"
            disabled={deleteCredential.isPending || readOnly}
          >
            {t("actions.delete")}
          </Button>
        );

        if (readOnly) {
          return (
            <div className="flex items-center gap-2">
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger>
                    <span tabIndex={0}>{updateBtn}</span>
                  </TooltipTrigger>
                  <TooltipContent>{t("readOnlyTooltip")}</TooltipContent>
                </Tooltip>
              </TooltipProvider>
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger>
                    <span tabIndex={0}>{deleteBtn}</span>
                  </TooltipTrigger>
                  <TooltipContent>{t("readOnlyTooltip")}</TooltipContent>
                </Tooltip>
              </TooltipProvider>
            </div>
          );
        }

        return (
          <div className="flex items-center gap-2">
            {updateBtn}
            <ConfirmDialog
              trigger={deleteBtn}
              title={t("deleteDialog.title", { server: c.server })}
              description={t("deleteDialog.description")}
              confirmLabel={t("deleteDialog.confirm")}
              isPending={deleteCredential.isPending}
              onConfirm={() => {
                deleteCredential.mutate(c.server, {
                  onSuccess: () =>
                    toast.success(t("toast.deleted", { server: c.server })),
                  onError: (err) => {
                    const msg =
                      err instanceof ApiError
                        ? err.message
                        : t("toast.deleteFailed");
                    toast.error(msg);
                  },
                });
              }}
            />
          </div>
        );
      },
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">
            {t("title")}
          </h1>
          <p className="text-sm text-muted-foreground">{t("description")}</p>
        </div>
        <AddCredentialButton readOnly={readOnly} onClick={() => setAddOpen(true)} />
      </div>

      {credentials.isLoading ? (
        <div className="overflow-hidden rounded-lg border border-border">
          {[...Array(3)].map((_, i) => (
            <div
              key={i}
              className="flex h-12 items-center border-b border-border px-3 last:border-b-0"
            >
              <Skeleton className="h-4 w-full" />
            </div>
          ))}
        </div>
      ) : credentials.data && credentials.data.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-4 rounded-lg border border-border py-16">
          <KeyRoundIcon
            className="size-8 text-muted-foreground"
            aria-hidden="true"
          />
          <p className="text-sm text-muted-foreground">
            {t("empty.description")}
          </p>
          <AddCredentialButton
            readOnly={readOnly}
            onClick={() => setAddOpen(true)}
          />
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border">
          <DataTable
            columns={columns}
            data={credentials.data ?? []}
            getKey={(c) => c.server}
          />
        </div>
      )}

      {/* Add dialog */}
      <CredentialDialog
        open={addOpen}
        onOpenChange={setAddOpen}
      />

      {/* Update dialog — keyed so state resets on server change */}
      {editServer !== null && (
        <CredentialDialog
          key={editServer}
          open={editServer !== null}
          onOpenChange={(o) => { if (!o) setEditServer(null); }}
          prefillServer={editServer}
        />
      )}
    </div>
  );
}
