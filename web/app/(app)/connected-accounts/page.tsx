"use client";
import { useState, type ReactNode } from "react";
import { toast } from "sonner";
import { useTranslations } from "next-intl";
import { ChevronDownIcon, ChevronRightIcon, PlugIcon } from "lucide-react";
import { useCredentials, usePutCredential, useDeleteCredential, useReadOnly } from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { DataTable } from "@/components/data-table";
import { OAuthConnections } from "./oauth-connections";
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

/* ------------------------------------------------------------------ */
/* Validation / body-building helpers                                  */
/* ------------------------------------------------------------------ */

interface AdvancedFieldsState {
  injectHeader: string;
  injectFormat: string;
  placeholder: string;
  allowedHosts: string;
}

const EMPTY_ADVANCED: AdvancedFieldsState = {
  injectHeader: "",
  injectFormat: "",
  placeholder: "",
  allowedHosts: "",
};

/** Newline- or comma-separated host list → trimmed, non-empty entries. */
function parseHostList(input: string): string[] {
  return input
    .split(/[\n,]+/)
    .map((h) => h.trim())
    .filter(Boolean);
}

/** PUT body from the form: only non-blank optional fields are included. */
function buildCredentialBody(
  secret: string,
  advanced: AdvancedFieldsState,
): CredentialPutBody {
  const body: CredentialPutBody = { secret };
  const injectHeader = advanced.injectHeader.trim();
  if (injectHeader) body.inject_header = injectHeader;
  const injectFormat = advanced.injectFormat.trim();
  if (injectFormat) body.inject_format = injectFormat;
  const placeholder = advanced.placeholder.trim();
  if (placeholder) body.placeholder = placeholder;
  if (advanced.allowedHosts.trim()) {
    body.allowed_hosts = parseHostList(advanced.allowedHosts);
  }
  return body;
}

/* ------------------------------------------------------------------ */
/* Dialog field groups                                                 */
/* ------------------------------------------------------------------ */

/** Label + control + optional hint, with the shared field spacing. */
function FormField({
  id,
  label,
  hint,
  children,
}: {
  id: string;
  label: string;
  hint?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {hint != null && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

function ServerField({
  value,
  onChange,
  disabled,
}: {
  value: string;
  onChange: (v: string) => void;
  disabled: boolean;
}) {
  const t = useTranslations("connectedAccounts");
  return (
    <FormField
      id="cred-server"
      label={t("form.server.label")}
      hint={t.rich("form.server.hint", { ...codeTag, pattern: SERVER_PATTERN })}
    >
      <Input
        id="cred-server"
        placeholder={t("form.server.placeholder")}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        className="font-mono"
      />
    </FormField>
  );
}

/** Write-only secret entry — never prefilled, never echoed back. */
function SecretField({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) {
  const t = useTranslations("connectedAccounts");
  return (
    <FormField id="cred-secret" label={t("form.secret.label")}>
      <textarea
        id="cred-secret"
        className={textareaClass}
        placeholder={t("form.secret.placeholder")}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete="off"
        spellCheck={false}
      />
    </FormField>
  );
}

function AdvancedToggle({
  open,
  onToggle,
}: {
  open: boolean;
  onToggle: () => void;
}) {
  const t = useTranslations("connectedAccounts");
  return (
    <button
      type="button"
      onClick={onToggle}
      className="flex items-center gap-1 text-xs text-muted-foreground transition-colors duration-150 ease-out hover:text-foreground"
    >
      {open ? (
        <ChevronDownIcon className="size-3.5" aria-hidden="true" />
      ) : (
        <ChevronRightIcon className="size-3.5" aria-hidden="true" />
      )}
      {t("form.advanced.toggle")}
    </button>
  );
}

function AdvancedFields({
  values,
  onChange,
}: {
  values: AdvancedFieldsState;
  onChange: (patch: Partial<AdvancedFieldsState>) => void;
}) {
  const t = useTranslations("connectedAccounts");
  return (
    <div className="mt-3 space-y-4">
      <Separator />
      <p className="text-xs text-muted-foreground">{t("form.advanced.note")}</p>

      <FormField
        id="cred-inject-header"
        label={t("form.injectHeader.label")}
        hint={t.rich("form.injectHeader.hint", {
          ...codeTag,
          pattern: HEADER_PATTERN,
        })}
      >
        <Input
          id="cred-inject-header"
          placeholder={t("form.injectHeader.placeholder")}
          value={values.injectHeader}
          onChange={(e) => onChange({ injectHeader: e.target.value })}
          className="font-mono"
        />
      </FormField>

      <FormField
        id="cred-inject-format"
        label={t("form.injectFormat.label")}
        hint={t.rich("form.injectFormat.hint", codeTag)}
      >
        <Input
          id="cred-inject-format"
          placeholder={t("form.injectFormat.placeholder")}
          value={values.injectFormat}
          onChange={(e) => onChange({ injectFormat: e.target.value })}
          className="font-mono"
        />
      </FormField>

      <FormField
        id="cred-placeholder"
        label={t("form.placeholder.label")}
        hint={t("form.placeholder.hint")}
      >
        <Input
          id="cred-placeholder"
          placeholder={t("form.placeholder.placeholder")}
          value={values.placeholder}
          onChange={(e) => onChange({ placeholder: e.target.value })}
          className="font-mono"
        />
      </FormField>

      <FormField
        id="cred-allowed-hosts"
        label={t("form.allowedHosts.label")}
        hint={t.rich("form.allowedHosts.hint", {
          ...codeTag,
          pattern: HOST_PATTERN,
        })}
      >
        <textarea
          id="cred-allowed-hosts"
          className={textareaClass}
          placeholder={t("form.allowedHosts.placeholder")}
          value={values.allowedHosts}
          onChange={(e) => onChange({ allowedHosts: e.target.value })}
          spellCheck={false}
        />
      </FormField>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Create / edit dialog                                                */
/* ------------------------------------------------------------------ */

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
  const t = useTranslations("connectedAccounts");
  const [server, setServer] = useState(prefillServer ?? "");
  const [secret, setSecret] = useState("");
  const [advanced, setAdvanced] = useState<AdvancedFieldsState>(EMPTY_ADVANCED);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const put = usePutCredential();
  const canSubmit = Boolean(server.trim()) && Boolean(secret);

  function reset() {
    setServer(prefillServer ?? "");
    setSecret("");
    setAdvanced(EMPTY_ADVANCED);
    setShowAdvanced(false);
    setError(null);
  }

  function handleOpenChange(o: boolean) {
    if (!o) reset();
    onOpenChange(o);
  }

  function handleSubmit() {
    if (!canSubmit) return;
    setError(null);

    put.mutate(
      { server: server.trim(), body: buildCredentialBody(secret, advanced) },
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
          <ServerField
            value={server}
            onChange={setServer}
            disabled={!!prefillServer}
          />
          <SecretField value={secret} onChange={setSecret} />

          <div>
            <AdvancedToggle
              open={showAdvanced}
              onToggle={() => setShowAdvanced((v) => !v)}
            />
            {showAdvanced && (
              <AdvancedFields
                values={advanced}
                onChange={(patch) =>
                  setAdvanced((prev) => ({ ...prev, ...patch }))
                }
              />
            )}
          </div>

          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>

        <DialogFooter>
          <Button onClick={handleSubmit} disabled={put.isPending || !canSubmit}>
            {put.isPending ? t("dialog.saving") : t("dialog.save")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ------------------------------------------------------------------ */
/* Read-only gating + table cells                                      */
/* ------------------------------------------------------------------ */

/** Wraps a disabled control with the impersonation-mode explanation. */
function ReadOnlyTooltip({ children }: { children: ReactNode }) {
  const t = useTranslations("connectedAccounts");
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

/** Primary action, disabled with an explanatory tooltip while impersonating. */
function AddCredentialButton({
  readOnly,
  onClick,
}: {
  readOnly: boolean;
  onClick: () => void;
}) {
  const t = useTranslations("connectedAccounts");
  if (readOnly) {
    return (
      <ReadOnlyTooltip>
        <Button disabled>{t("add")}</Button>
      </ReadOnlyTooltip>
    );
  }
  return <Button onClick={onClick}>{t("add")}</Button>;
}

function CredentialActionsCell({
  credential,
  readOnly,
  deleteCredential,
  onEdit,
}: {
  credential: Credential;
  readOnly: boolean;
  deleteCredential: ReturnType<typeof useDeleteCredential>;
  onEdit: (server: string) => void;
}) {
  const t = useTranslations("connectedAccounts");

  const updateBtn = (
    <Button
      variant="outline"
      size="sm"
      disabled={readOnly}
      onClick={() => !readOnly && onEdit(credential.server)}
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
        <ReadOnlyTooltip>{updateBtn}</ReadOnlyTooltip>
        <ReadOnlyTooltip>{deleteBtn}</ReadOnlyTooltip>
      </div>
    );
  }

  function handleDelete() {
    deleteCredential.mutate(credential.server, {
      onSuccess: () =>
        toast.success(t("toast.deleted", { server: credential.server })),
      onError: (err) => {
        const msg =
          err instanceof ApiError ? err.message : t("toast.deleteFailed");
        toast.error(msg);
      },
    });
  }

  return (
    <div className="flex items-center gap-2">
      {updateBtn}
      <ConfirmDialog
        trigger={deleteBtn}
        title={t("deleteDialog.title", { server: credential.server })}
        description={t("deleteDialog.description")}
        confirmLabel={t("deleteDialog.confirm")}
        isPending={deleteCredential.isPending}
        onConfirm={handleDelete}
      />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

export default function ConnectedAccountsPage() {
  const t = useTranslations("connectedAccounts");
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
      cell: (c) => (
        <CredentialActionsCell
          credential={c}
          readOnly={readOnly}
          deleteCredential={deleteCredential}
          onEdit={setEditServer}
        />
      ),
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

      {/* OAuth connections */}
      <OAuthConnections />

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
          <PlugIcon
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
