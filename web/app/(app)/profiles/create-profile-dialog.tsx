"use client";
import { useState } from "react";
import { toast } from "sonner";
import { useTranslations } from "next-intl";
import { useCreateProfile } from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
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

export function CreateProfileTrigger({
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

function useCreateProfileForm({
  onOpenChange,
  onReveal,
}: {
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

  return {
    name,
    setName,
    slug,
    setSlug,
    error,
    isPending: create.isPending,
    handleOpen,
    handleCreate,
  };
}

export function CreateProfileDialog({
  open,
  onOpenChange,
  onReveal,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onReveal: (token: string) => void;
}) {
  const t = useTranslations("profiles");
  const form = useCreateProfileForm({ onOpenChange, onReveal });

  return (
    <Dialog open={open} onOpenChange={form.handleOpen}>
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
              value={form.name}
              onChange={(e) => form.setName(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="profile-slug">{t("create.slugLabel")}</Label>
            <Input
              id="profile-slug"
              className="font-mono"
              placeholder={t("create.slugPlaceholder")}
              value={form.slug}
              onChange={(e) => form.setSlug(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") form.handleCreate();
              }}
            />
            <p className="text-xs text-muted-foreground">
              {t("create.slugHint")}
            </p>
          </div>
          {form.error && (
            <p className="text-sm text-destructive">{form.error}</p>
          )}
        </div>
        <DialogFooter>
          <Button
            onClick={form.handleCreate}
            disabled={form.isPending || !form.name.trim() || !form.slug.trim()}
          >
            {form.isPending ? t("create.submitting") : t("create.submit")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
