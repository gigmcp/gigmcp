"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { useTranslations } from "next-intl";
import {
  useRenameProfile,
  useRotateToken,
  useDeleteProfile,
} from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { Profile } from "@/lib/types";

export function toastMutationError(err: unknown, fallback: string) {
  toast.error(err instanceof ApiError ? err.message : fallback);
}

export function ReadOnlyTooltip({
  readOnly,
  children,
}: {
  readOnly: boolean;
  children: React.ReactNode;
}) {
  const t = useTranslations("profiles");

  if (!readOnly) return <>{children}</>;

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

export function EndpointCard({ endpoint }: { endpoint: string }) {
  const t = useTranslations("profiles");

  function copyEndpoint() {
    navigator.clipboard
      .writeText(endpoint)
      .then(() => toast.success(t("detail.endpoint.copiedToast")));
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("detail.endpoint.title")}</CardTitle>
        <CardDescription>{t("detail.endpoint.description")}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-2">
          <code className="flex-1 overflow-x-auto rounded-md border border-border bg-muted px-3 py-2 font-mono text-xs whitespace-nowrap">
            {endpoint}
          </code>
          <Button variant="outline" size="sm" onClick={copyEndpoint}>
            {t("detail.endpoint.copy")}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export function RenameCard({
  profile: p,
  initialName,
  readOnly,
}: {
  profile: Profile;
  initialName: string;
  readOnly: boolean;
}) {
  const t = useTranslations("profiles");
  const rename = useRenameProfile();
  const [profileName, setProfileName] = useState(initialName);

  function handleRename() {
    const trimmed = profileName.trim();
    if (!trimmed || trimmed === p.name) return;
    rename.mutate(
      { id: p.id, name: trimmed },
      {
        onSuccess: () => toast.success(t("detail.rename.successToast")),
        onError: (err) => toastMutationError(err, t("detail.rename.failed")),
      },
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("detail.rename.title")}</CardTitle>
        <CardDescription>{t("detail.rename.description")}</CardDescription>
      </CardHeader>
      <CardContent>
        <Label htmlFor="rename-input" className="sr-only">
          {t("detail.rename.inputLabel")}
        </Label>
        <Input
          id="rename-input"
          value={profileName}
          disabled={readOnly}
          onChange={(e) => setProfileName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !readOnly) handleRename();
          }}
        />
      </CardContent>
      <CardFooter className="justify-end">
        <ReadOnlyTooltip readOnly={readOnly}>
          <Button
            variant="outline"
            size="sm"
            onClick={handleRename}
            disabled={
              rename.isPending ||
              readOnly ||
              !profileName.trim() ||
              profileName.trim() === p.name
            }
          >
            {rename.isPending
              ? t("detail.rename.submitting")
              : t("detail.rename.submit")}
          </Button>
        </ReadOnlyTooltip>
      </CardFooter>
    </Card>
  );
}

export function RotateTokenCard({
  profileId,
  readOnly,
  onReveal,
}: {
  profileId: Profile["id"];
  readOnly: boolean;
  onReveal: (token: string) => void;
}) {
  const t = useTranslations("profiles");
  const rotateToken = useRotateToken();

  function handleRotateToken() {
    rotateToken.mutate(profileId, {
      onSuccess: (updated) => {
        if (updated.token) {
          onReveal(updated.token);
        } else {
          toast.success(t("detail.rotate.successToast"));
        }
      },
      onError: (err) => toastMutationError(err, t("detail.rotate.failed")),
    });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("detail.rotate.title")}</CardTitle>
        <CardDescription>{t("detail.rotate.description")}</CardDescription>
      </CardHeader>
      <CardFooter className="justify-end">
        <ReadOnlyTooltip readOnly={readOnly}>
          <Button
            variant="outline"
            size="sm"
            onClick={handleRotateToken}
            disabled={rotateToken.isPending || readOnly}
          >
            {rotateToken.isPending
              ? t("detail.rotate.submitting")
              : t("detail.rotate.submit")}
          </Button>
        </ReadOnlyTooltip>
      </CardFooter>
    </Card>
  );
}

export function DeleteCard({
  profile: p,
  readOnly,
}: {
  profile: Profile;
  readOnly: boolean;
}) {
  const t = useTranslations("profiles");
  const router = useRouter();
  const deleteProfile = useDeleteProfile();

  function handleDelete() {
    deleteProfile.mutate(p.id, {
      onSuccess: () => {
        toast.success(t("detail.delete.successToast"));
        router.push("/profiles");
      },
      onError: (err) => toastMutationError(err, t("detail.delete.failed")),
    });
  }

  return (
    <Card className="border-destructive/50">
      <CardHeader>
        <CardTitle className="text-destructive">
          {t("detail.delete.title")}
        </CardTitle>
        <CardDescription>{t("detail.delete.description")}</CardDescription>
      </CardHeader>
      <CardFooter className="justify-end">
        {readOnly ? (
          <ReadOnlyTooltip readOnly={readOnly}>
            <Button variant="destructive" size="sm" disabled>
              {t("detail.delete.submit")}
            </Button>
          </ReadOnlyTooltip>
        ) : (
          <ConfirmDialog
            trigger={
              <Button
                variant="destructive"
                size="sm"
                disabled={deleteProfile.isPending}
              >
                {t("detail.delete.submit")}
              </Button>
            }
            title={t("detail.delete.confirmTitle", { name: p.name })}
            description={t("detail.delete.confirmDescription")}
            confirmLabel={t("detail.delete.confirmLabel")}
            isPending={deleteProfile.isPending}
            onConfirm={handleDelete}
          />
        )}
      </CardFooter>
    </Card>
  );
}
