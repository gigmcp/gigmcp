"use client";
import { useState } from "react";
import { toast } from "sonner";
import { useCredentials, usePutCredential, useDeleteCredential } from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { DataTable } from "@/components/data-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
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
import { Separator } from "@/components/ui/separator";
import type { Credential, CredentialPutBody } from "@/lib/types";
import type { Column } from "@/components/data-table";

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
          toast.success(`Credential for "${server.trim()}" saved`);
          handleOpenChange(false);
        },
        onError: (err) => {
          if (err instanceof ApiError) {
            setError(err.message);
          } else {
            setError("Failed to save credential");
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
            {prefillServer ? `Update credential — ${prefillServer}` : "Add credential"}
          </DialogTitle>
          <DialogDescription>
            Secrets are write-only. Saving replaces the existing secret; nothing
            is ever displayed.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="cred-server">Server name</Label>
            <Input
              id="cred-server"
              placeholder="e.g. my-server"
              value={server}
              onChange={(e) => setServer(e.target.value)}
              disabled={!!prefillServer}
            />
            <p className="text-xs text-muted-foreground">
              Pattern: <span className="font-mono">^[a-z0-9][a-z0-9_-]&#123;0,63&#125;$</span>
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="cred-secret">Secret</Label>
            <textarea
              id="cred-secret"
              className="h-20 w-full min-w-0 rounded-lg border border-input bg-transparent px-2.5 py-1.5 font-mono text-sm transition-colors outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50 resize-none"
              placeholder="Paste your secret here…"
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
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
            >
              <span>{showAdvanced ? "▾" : "▸"}</span>
              Advanced (transitional)
            </button>

            {showAdvanced && (
              <div className="mt-3 space-y-4">
                <Separator />
                <p className="text-xs text-muted-foreground">
                  These fields will be sourced from the manifest in a future
                  release.
                </p>

                <div className="space-y-2">
                  <Label htmlFor="cred-inject-header">
                    Inject header
                  </Label>
                  <Input
                    id="cred-inject-header"
                    placeholder="Authorization"
                    value={injectHeader}
                    onChange={(e) => setInjectHeader(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">
                    Pattern: <span className="font-mono">^[A-Za-z0-9-]+$</span>, max 64 chars.
                  </p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="cred-inject-format">
                    Inject format
                  </Label>
                  <Input
                    id="cred-inject-format"
                    placeholder="Bearer {token}"
                    value={injectFormat}
                    onChange={(e) => setInjectFormat(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">
                    Must contain <span className="font-mono">&#123;token&#125;</span>, max 256 chars.
                  </p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="cred-placeholder">Placeholder</Label>
                  <Input
                    id="cred-placeholder"
                    placeholder="REPLACE_ME"
                    value={placeholder}
                    onChange={(e) => setPlaceholder(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">
                    8–256 chars.
                  </p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="cred-allowed-hosts">
                    Allowed hosts
                  </Label>
                  <textarea
                    id="cred-allowed-hosts"
                    className="h-20 w-full min-w-0 rounded-lg border border-input bg-transparent px-2.5 py-1.5 font-mono text-sm transition-colors outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50 resize-none"
                    placeholder={"api.example.com\n*.other.com"}
                    value={allowedHosts}
                    onChange={(e) => setAllowedHosts(e.target.value)}
                    spellCheck={false}
                  />
                  <p className="text-xs text-muted-foreground">
                    One host per line (or comma-separated). Each up to 253 chars,
                    pattern <span className="font-mono">^(\*\.)?[a-z0-9.-]+$</span>.
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
            {put.isPending ? "Saving…" : "Save credential"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function CredentialsPage() {
  const credentials = useCredentials();
  const deleteCredential = useDeleteCredential();
  const [addOpen, setAddOpen] = useState(false);
  const [editServer, setEditServer] = useState<string | null>(null);

  const columns: Column<Credential>[] = [
    { header: "Server", cell: (c) => <span className="font-mono text-sm">{c.server}</span> },
    {
      header: "Inject header",
      cell: (c) =>
        c.inject_header ? (
          <span className="font-mono text-xs">{c.inject_header}</span>
        ) : (
          <span className="text-muted-foreground">—</span>
        ),
    },
    {
      header: "Allowed hosts",
      cell: (c) =>
        c.allowed_hosts.length > 0 ? (
          <span>{c.allowed_hosts.length} host{c.allowed_hosts.length === 1 ? "" : "s"}</span>
        ) : (
          <span className="text-muted-foreground">—</span>
        ),
    },
    {
      header: "Actions",
      cell: (c) => (
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setEditServer(c.server)}
          >
            Update
          </Button>
          <ConfirmDialog
            trigger={
              <Button
                variant="destructive"
                size="sm"
                disabled={deleteCredential.isPending}
              >
                Delete
              </Button>
            }
            title={`Delete credential for "${c.server}"?`}
            description="The stored secret will be permanently removed."
            confirmLabel="Delete"
            isPending={deleteCredential.isPending}
            onConfirm={() => {
              deleteCredential.mutate(c.server, {
                onSuccess: () =>
                  toast.success(`Credential for "${c.server}" deleted`),
                onError: (err) => {
                  const msg =
                    err instanceof ApiError ? err.message : "Delete failed";
                  toast.error(msg);
                },
              });
            }}
          />
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Credentials</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Write-only secrets injected into MCP server requests. Secrets are
            never displayed.
          </p>
        </div>
        <Button onClick={() => setAddOpen(true)}>Add credential</Button>
      </div>

      {credentials.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : (
        <DataTable
          columns={columns}
          data={credentials.data ?? []}
          getKey={(c) => c.server}
        />
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
