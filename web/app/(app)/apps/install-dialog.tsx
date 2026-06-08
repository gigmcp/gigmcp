"use client";
import { useMemo, useState } from "react";
import { useTranslations } from "next-intl";
import {
  CheckIcon,
  PackageOpenIcon,
  SearchIcon,
  TriangleAlertIcon,
} from "lucide-react";
import { toast } from "sonner";
import { useCatalog, useInstallServer, useApps } from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";
import { monogram, monogramColor } from "@/lib/monogram";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import type { CatalogServer } from "@/lib/types";

export function ReadOnlyTooltip({ children }: { children: React.ReactNode }) {
  const t = useTranslations("apps");
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

function CatalogRow({
  server,
  installed,
  selected,
  onSelect,
}: {
  server: CatalogServer;
  installed: boolean;
  selected: boolean;
  onSelect: () => void;
}) {
  const t = useTranslations("apps");
  return (
    <button
      type="button"
      disabled={installed}
      aria-pressed={selected}
      onClick={onSelect}
      className={cn(
        "flex w-full items-center gap-3 px-3 py-2.5 text-left transition-colors outline-none focus-visible:bg-muted",
        installed ? "cursor-default opacity-60" : "hover:bg-muted",
        selected && "bg-muted",
      )}
    >
      <span
        className="flex size-8 shrink-0 items-center justify-center rounded-md text-xs font-semibold text-white"
        style={{ backgroundColor: monogramColor(server.name) }}
        aria-hidden
      >
        {monogram(server.name)}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate font-mono text-sm">{server.name}</span>
          {installed && (
            <Badge variant="success">{t("install.installedBadge")}</Badge>
          )}
        </div>
        {server.description && (
          <p className="mt-0.5 truncate text-xs text-muted-foreground">
            {server.description}
          </p>
        )}
      </div>
      <Badge variant="outline" className="shrink-0 font-mono">
        {server.latest}
      </Badge>
      {selected && <CheckIcon className="size-4 shrink-0" aria-hidden />}
    </button>
  );
}

export function InstallDialog({ disabled }: { disabled?: boolean }) {
  const t = useTranslations("apps");
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<CatalogServer | null>(null);
  const [byRef, setByRef] = useState(false);
  const [ref, setRef] = useState("");

  const catalog = useCatalog(open);
  const apps = useApps();
  const install = useInstallServer();

  const installedNames = useMemo(
    () => new Set((apps.data ?? []).map((a) => a.name)),
    [apps.data],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const all = catalog.data ?? [];
    if (!q) return all;
    return all.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        (s.description ?? "").toLowerCase().includes(q),
    );
  }, [catalog.data, search]);

  const registryDisabled =
    catalog.error instanceof ApiError &&
    catalog.error.code === "registry_disabled";

  function handleOpenChange(next: boolean) {
    setOpen(next);
    if (!next) {
      setSearch("");
      setSelected(null);
      setByRef(false);
      setRef("");
    }
  }

  function doInstall(refValue: string) {
    install.mutate(refValue, {
      onSuccess: (server) => {
        toast.success(t("install.success", { name: server.name }));
        handleOpenChange(false);
      },
      onError: (err) => {
        const msg = err instanceof ApiError ? err.message : t("install.error");
        toast.error(msg);
      },
    });
  }

  const trigger = (
    <Button size="sm" onClick={() => setOpen(true)} disabled={disabled}>
      {t("install.button")}
    </Button>
  );

  const showRefForm = byRef || registryDisabled;
  const canSubmit = selected !== null || (showRefForm && ref.trim() !== "");

  return (
    <>
      {disabled ? <ReadOnlyTooltip>{trigger}</ReadOnlyTooltip> : trigger}
      <Dialog open={open} onOpenChange={handleOpenChange}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{t("install.dialogTitle")}</DialogTitle>
            <DialogDescription>
              {t("install.dialogDescription")}
            </DialogDescription>
          </DialogHeader>

          {registryDisabled ? (
            <div className="flex flex-col items-center gap-2 rounded-md border border-border px-6 py-8 text-center">
              <PackageOpenIcon className="size-5 text-muted-foreground" aria-hidden />
              <p className="text-sm font-medium">
                {t("install.registryDisabled.title")}
              </p>
              <p className="text-xs text-muted-foreground">
                {t("install.registryDisabled.description")}
              </p>
            </div>
          ) : catalog.isError ? (
            <div className="flex flex-col items-center gap-3 rounded-md border border-border px-6 py-8 text-center">
              <TriangleAlertIcon className="size-5 text-muted-foreground" aria-hidden />
              <p className="text-sm text-muted-foreground">
                {t("install.registryUnavailable.title")}
              </p>
              <Button variant="outline" size="sm" onClick={() => catalog.refetch()}>
                {t("install.registryUnavailable.retry")}
              </Button>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="relative">
                <SearchIcon
                  className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground"
                  aria-hidden
                />
                <Input
                  className="pl-9"
                  placeholder={t("install.searchPlaceholder")}
                  aria-label={t("install.searchPlaceholder")}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>
              <div className="max-h-72 divide-y divide-border overflow-y-auto rounded-md border border-border">
                {catalog.isLoading ? (
                  [...Array(5)].map((_, i) => (
                    <div key={i} className="flex items-center gap-3 px-3 py-2.5">
                      <Skeleton className="size-8 rounded-md" />
                      <div className="flex-1 space-y-1.5">
                        <Skeleton className="h-4 w-32" />
                        <Skeleton className="h-3 w-56" />
                      </div>
                      <Skeleton className="h-5 w-12 rounded-full" />
                    </div>
                  ))
                ) : filtered.length === 0 ? (
                  <p className="px-3 py-8 text-center text-sm text-muted-foreground">
                    {search.trim()
                      ? t("install.noResults")
                      : t("install.emptyCatalog")}
                  </p>
                ) : (
                  filtered.map((s) => (
                    <CatalogRow
                      key={s.name}
                      server={s}
                      installed={installedNames.has(s.name)}
                      selected={selected?.name === s.name}
                      onSelect={() => {
                        setSelected(selected?.name === s.name ? null : s);
                        setByRef(false);
                        setRef("");
                      }}
                    />
                  ))
                )}
              </div>
            </div>
          )}

          {showRefForm ? (
            <div className="space-y-2">
              <Label htmlFor="install-ref">{t("install.refLabel")}</Label>
              <Input
                id="install-ref"
                className="font-mono"
                placeholder={t("install.refPlaceholder")}
                value={ref}
                onChange={(e) => setRef(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && ref.trim()) doInstall(ref.trim());
                }}
              />
            </div>
          ) : (
            <button
              type="button"
              className="w-fit text-xs text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
              onClick={() => {
                setByRef(true);
                setSelected(null);
              }}
            >
              {t("install.byRefToggle")}
            </button>
          )}

          <DialogFooter>
            <Button
              disabled={install.isPending || !canSubmit}
              onClick={() => {
                if (selected) doInstall(selected.name);
                else if (ref.trim()) doInstall(ref.trim());
              }}
            >
              {install.isPending
                ? t("install.submitting")
                : selected
                  ? t("install.confirmInstall", { name: selected.name })
                  : t("install.submit")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
