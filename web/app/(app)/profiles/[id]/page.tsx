"use client";
import { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { toast } from "sonner";
import { useTranslations } from "next-intl";
import {
  useProfile,
  useServers,
  useSetProfileServers,
  useRenameProfile,
  useRotateToken,
  useDeleteProfile,
  useReadOnly,
} from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { TokenRevealDialog } from "@/components/token-reveal-dialog";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
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

interface ProfileDetailProps {
  profile: Profile;
  initialName: string;
  initialServers: Set<string>;
  readOnly: boolean;
}

// Inner component is keyed by profile id so React remounts it (and thus
// re-runs all useState initialisers) whenever navigation switches profile.
function ProfileDetail({
  profile: p,
  initialName,
  initialServers,
  readOnly,
}: ProfileDetailProps) {
  const t = useTranslations("profiles");
  const router = useRouter();

  const setServersMut = useSetProfileServers();
  const rename = useRenameProfile();
  const rotateToken = useRotateToken();
  const deleteProfile = useDeleteProfile();
  const servers = useServers();

  const [profileName, setProfileName] = useState(initialName);
  const [selectedServers, setSelectedServers] = useState<Set<string>>(initialServers);
  const [revealToken, setRevealToken] = useState<string | null>(null);

  // Derive endpoint URL at render time.
  const endpoint =
    typeof window !== "undefined"
      ? `${window.location.origin}${p.endpoint}`
      : p.endpoint;

  function toggleServer(name: string, checked: boolean) {
    setSelectedServers((prev) => {
      const next = new Set(prev);
      if (checked) next.add(name);
      else next.delete(name);
      return next;
    });
  }

  function handleSaveBundle() {
    setServersMut.mutate(
      { id: p.id, servers: Array.from(selectedServers) },
      {
        onSuccess: () => toast.success(t("detail.bundle.savedToast")),
        onError: (err) => {
          const msg =
            err instanceof ApiError ? err.message : t("detail.bundle.saveFailed");
          toast.error(msg);
        },
      },
    );
  }

  function handleRename() {
    const trimmed = profileName.trim();
    if (!trimmed || trimmed === p.name) return;
    rename.mutate(
      { id: p.id, name: trimmed },
      {
        onSuccess: () => toast.success(t("detail.rename.successToast")),
        onError: (err) => {
          const msg =
            err instanceof ApiError ? err.message : t("detail.rename.failed");
          toast.error(msg);
        },
      },
    );
  }

  function handleRotateToken() {
    rotateToken.mutate(p.id, {
      onSuccess: (updated) => {
        if (updated.token) {
          setRevealToken(updated.token);
        } else {
          toast.success(t("detail.rotate.successToast"));
        }
      },
      onError: (err) => {
        const msg =
          err instanceof ApiError ? err.message : t("detail.rotate.failed");
        toast.error(msg);
      },
    });
  }

  function handleDelete() {
    deleteProfile.mutate(p.id, {
      onSuccess: () => {
        toast.success(t("detail.delete.successToast"));
        router.push("/profiles");
      },
      onError: (err) => {
        const msg =
          err instanceof ApiError ? err.message : t("detail.delete.failed");
        toast.error(msg);
      },
    });
  }

  function copyEndpoint() {
    navigator.clipboard
      .writeText(endpoint)
      .then(() => toast.success(t("detail.endpoint.copiedToast")));
  }

  function maybeWrapTooltip(btn: React.ReactNode) {
    if (!readOnly) return btn;
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger>
            <span tabIndex={0}>{btn}</span>
          </TooltipTrigger>
          <TooltipContent>{t("readOnlyTooltip")}</TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{p.name}</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {t.rich("detail.description", {
            slug: p.slug,
            mono: (chunks) => (
              <span className="font-mono text-foreground">{chunks}</span>
            ),
          })}
        </p>
      </div>

      {/* Endpoint URL */}
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

      {/* Bundle editor */}
      <Card>
        <CardHeader>
          <CardTitle>{t("detail.bundle.title")}</CardTitle>
          <CardDescription>{t("detail.bundle.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          {servers.isLoading ? (
            <div className="space-y-2">
              {[...Array(3)].map((_, i) => (
                <Skeleton key={i} className="h-6 w-48 rounded" />
              ))}
            </div>
          ) : servers.data && servers.data.length > 0 ? (
            <div className="space-y-2">
              {servers.data.map((s) => (
                <label
                  key={s.name}
                  className={[
                    "flex cursor-pointer items-center gap-3",
                    readOnly ? "opacity-60 cursor-not-allowed" : "",
                  ].join(" ")}
                >
                  <Checkbox
                    checked={selectedServers.has(s.name)}
                    disabled={readOnly}
                    onCheckedChange={(checked) =>
                      !readOnly && toggleServer(s.name, checked as boolean)
                    }
                  />
                  <span className="font-mono text-[13px]">{s.name}</span>
                </label>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              {t("detail.bundle.noServers")}
            </p>
          )}
        </CardContent>
        {servers.data && servers.data.length > 0 && (
          <CardFooter className="justify-end">
            {maybeWrapTooltip(
              <Button
                onClick={handleSaveBundle}
                disabled={setServersMut.isPending || readOnly}
                size="sm"
              >
                {setServersMut.isPending
                  ? t("detail.bundle.saving")
                  : t("detail.bundle.save")}
              </Button>,
            )}
          </CardFooter>
        )}
      </Card>

      {/* Rename */}
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
          {maybeWrapTooltip(
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
            </Button>,
          )}
        </CardFooter>
      </Card>

      {/* Token rotation */}
      <Card>
        <CardHeader>
          <CardTitle>{t("detail.rotate.title")}</CardTitle>
          <CardDescription>{t("detail.rotate.description")}</CardDescription>
        </CardHeader>
        <CardFooter className="justify-end">
          {maybeWrapTooltip(
            <Button
              variant="outline"
              size="sm"
              onClick={handleRotateToken}
              disabled={rotateToken.isPending || readOnly}
            >
              {rotateToken.isPending
                ? t("detail.rotate.submitting")
                : t("detail.rotate.submit")}
            </Button>,
          )}
        </CardFooter>
      </Card>

      {/* Delete */}
      <Card className="border-destructive/50">
        <CardHeader>
          <CardTitle className="text-destructive">
            {t("detail.delete.title")}
          </CardTitle>
          <CardDescription>{t("detail.delete.description")}</CardDescription>
        </CardHeader>
        <CardFooter className="justify-end">
          {readOnly ? (
            maybeWrapTooltip(
              <Button variant="destructive" size="sm" disabled>
                {t("detail.delete.submit")}
              </Button>,
            )
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

      <TokenRevealDialog
        open={!!revealToken}
        token={revealToken ?? ""}
        onClose={() => setRevealToken(null)}
      />
    </div>
  );
}

export default function ProfileDetailPage() {
  const t = useTranslations("profiles");
  const params = useParams();
  const id = Number(params.id);
  const profile = useProfile(id);
  const readOnly = useReadOnly();

  if (profile.isLoading) {
    return (
      <div className="max-w-2xl space-y-6">
        <div className="space-y-2">
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-4 w-72" />
        </div>
        <Skeleton className="h-36 w-full rounded-lg" />
        <Skeleton className="h-48 w-full rounded-lg" />
        <Skeleton className="h-36 w-full rounded-lg" />
      </div>
    );
  }

  if (!profile.data) {
    return (
      <p className="py-8 text-center text-sm text-destructive">
        {t("detail.notFound")}
      </p>
    );
  }

  const p = profile.data;

  return (
    <ProfileDetail
      key={p.id}
      profile={p}
      initialName={p.name}
      initialServers={new Set(p.servers)}
      readOnly={readOnly}
    />
  );
}
