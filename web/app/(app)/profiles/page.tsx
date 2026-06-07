"use client";
import { useState } from "react";
import Link from "next/link";
import { toast } from "sonner";
import { useFormatter, useTranslations } from "next-intl";
import { Layers } from "lucide-react";
import {
  useProfiles,
  useCreateProfile,
  useReadOnly,
} from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { DataTable } from "@/components/data-table";
import { TokenRevealDialog } from "@/components/token-reveal-dialog";
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
import type { Profile } from "@/lib/types";
import type { Column } from "@/components/data-table";

function CreateProfileTrigger({
  disabled,
  onClick,
}: {
  disabled?: boolean;
  onClick: () => void;
}) {
  const t = useTranslations("profiles");

  const trigger = (
    <Button onClick={onClick} disabled={disabled}>
      {t("create.trigger")}
    </Button>
  );

  if (!disabled) return trigger;

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger>
          <span tabIndex={0}>{trigger}</span>
        </TooltipTrigger>
        <TooltipContent>{t("readOnlyTooltip")}</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

function CreateProfileDialog({
  open,
  onOpenChange,
  onReveal,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onReveal: (token: string) => void;
}) {
  const t = useTranslations("profiles");
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [error, setError] = useState<string | null>(null);

  const create = useCreateProfile();

  function handleOpen(o: boolean) {
    onOpenChange(o);
    if (!o) {
      setName("");
      setSlug("");
      setError(null);
    }
  }

  function handleCreate() {
    if (!name.trim() || !slug.trim()) return;
    setError(null);
    create.mutate(
      { name: name.trim(), slug: slug.trim() },
      {
        onSuccess: (profile) => {
          onOpenChange(false);
          setName("");
          setSlug("");
          if (profile.token) {
            onReveal(profile.token);
          } else {
            toast.success(t("create.successToast", { name: profile.name }));
          }
        },
        onError: (err) => {
          if (err instanceof ApiError) {
            if (err.code === "conflict") {
              setError(t("create.errors.slugTaken"));
            } else {
              setError(err.message);
            }
          } else {
            setError(t("create.errors.generic"));
          }
        },
      },
    );
  }

  return (
    <Dialog open={open} onOpenChange={handleOpen}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("create.title")}</DialogTitle>
          <DialogDescription>{t("create.description")}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="profile-name">{t("create.nameLabel")}</Label>
            <Input
              id="profile-name"
              placeholder={t("create.namePlaceholder")}
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="profile-slug">{t("create.slugLabel")}</Label>
            <Input
              id="profile-slug"
              className="font-mono"
              placeholder={t("create.slugPlaceholder")}
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleCreate();
              }}
            />
            <p className="text-xs text-muted-foreground">
              {t("create.slugHint")}
            </p>
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button
            onClick={handleCreate}
            disabled={create.isPending || !name.trim() || !slug.trim()}
          >
            {create.isPending ? t("create.submitting") : t("create.submit")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function ProfilesPage() {
  const t = useTranslations("profiles");
  const format = useFormatter();
  const profiles = useProfiles();
  const readOnly = useReadOnly();
  const [createOpen, setCreateOpen] = useState(false);
  const [revealToken, setRevealToken] = useState<string | null>(null);

  const columns: Column<Profile>[] = [
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

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            {t("list.title")}
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {t("list.description")}
          </p>
        </div>
        <CreateProfileTrigger
          disabled={readOnly}
          onClick={() => setCreateOpen(true)}
        />
      </div>

      {profiles.isLoading ? (
        <div className="overflow-hidden rounded-lg border border-border">
          <div className="divide-y divide-border">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="flex h-12 items-center px-3">
                <Skeleton className="h-4 w-full" />
              </div>
            ))}
          </div>
        </div>
      ) : profiles.data && profiles.data.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-4 rounded-lg border border-border px-6 py-16 text-center">
          <Layers className="size-8 text-muted-foreground" aria-hidden="true" />
          <div className="space-y-1">
            <p className="text-sm font-medium">{t("list.empty.title")}</p>
            <p className="text-sm text-muted-foreground">
              {t("list.empty.description")}
            </p>
          </div>
          <Button disabled={readOnly} onClick={() => setCreateOpen(true)}>
            {t("create.trigger")}
          </Button>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border">
          <DataTable
            columns={columns}
            data={profiles.data ?? []}
            getKey={(p) => p.id}
          />
        </div>
      )}

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
