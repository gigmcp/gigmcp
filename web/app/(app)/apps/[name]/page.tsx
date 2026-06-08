"use client";
import { useParams } from "next/navigation";
import Link from "next/link";
import { useTranslations } from "next-intl";
import { toast } from "sonner";
import { ChevronLeft, ShieldCheck } from "lucide-react";
import { useApp, useProfiles, useSetProfileServers, useReadOnly } from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Skeleton } from "@/components/ui/skeleton";
import { monogram, monogramColor } from "@/lib/monogram";
import { ConnectBlock } from "./connect-block";
import type { Profile } from "@/lib/types";

const AUTH_BADGE_VARIANT = {
  oauth2: "info",
  api_key: "warning",
  basic: "secondary",
  custom_env: "outline",
  none: "outline",
} as const;

function ProfileToggle({
  profile,
  appName,
}: {
  profile: Profile;
  appName: string;
}) {
  const t = useTranslations("apps");
  const readOnly = useReadOnly();
  const setServers = useSetProfileServers();
  const checked = profile.servers.includes(appName);

  function toggle(next: boolean) {
    const servers = next
      ? [...profile.servers, appName]
      : profile.servers.filter((s) => s !== appName);
    setServers.mutate(
      { id: profile.id, servers },
      {
        onSuccess: () =>
          toast.success(t("detail.profiles.saved", { name: profile.name })),
        onError: (err) =>
          toast.error(
            err instanceof ApiError ? err.message : t("detail.profiles.saveFailed"),
          ),
      },
    );
  }

  return (
    <label className="flex items-center gap-3 rounded-lg border border-border p-3">
      <Checkbox
        checked={checked}
        disabled={readOnly || setServers.isPending}
        onCheckedChange={(v) => toggle(Boolean(v))}
      />
      <span className="text-sm font-medium">{profile.name}</span>
      <span className="font-mono text-xs text-muted-foreground">{profile.slug}</span>
    </label>
  );
}

export default function AppDetailPage() {
  const params = useParams<{ name: string }>();
  const name = params.name;
  const t = useTranslations("apps");
  const app = useApp(name);
  const profiles = useProfiles();

  if (app.isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-32 w-full rounded-xl" />
      </div>
    );
  }
  if (app.isError || !app.data) {
    return (
      <div className="space-y-4">
        <Link
          href="/apps"
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ChevronLeft className="size-4" /> {t("detail.back")}
        </Link>
        <p className="text-sm text-muted-foreground">{t("detail.notFound")}</p>
      </div>
    );
  }

  const d = app.data;

  return (
    <div className="space-y-8">
      <Link
        href="/apps"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ChevronLeft className="size-4" /> {t("detail.back")}
      </Link>

      {/* Header */}
      <div className="flex items-start gap-4">
        <span
          className="flex size-14 shrink-0 items-center justify-center rounded-xl text-lg font-semibold text-white"
          style={{ backgroundColor: monogramColor(d.name) }}
          aria-hidden
        >
          {monogram(d.name)}
        </span>
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl font-semibold tracking-tight">{d.display_name}</h1>
          <div className="mt-1 flex items-center gap-2">
            <Badge variant={AUTH_BADGE_VARIANT[d.auth_type]}>
              {t(`authType.${d.auth_type}`)}
            </Badge>
            {d.version && (
              <span className="text-xs text-muted-foreground">
                {t("detail.version", { version: d.version })}
              </span>
            )}
          </div>
          {d.description && (
            <p className="mt-2 text-sm text-muted-foreground">{d.description}</p>
          )}
        </div>
      </div>

      {/* Connect block */}
      <ConnectBlock app={d} />

      {/* Network access (enforced) */}
      <section className="rounded-xl border border-border p-4">
        <div className="flex items-center gap-2">
          <ShieldCheck className="size-4 text-muted-foreground" aria-hidden />
          <h2 className="text-base font-semibold tracking-tight">
            {t("detail.network.title")}
          </h2>
          <Badge variant="outline">{t("detail.network.enforced")}</Badge>
        </div>
        {d.allowed_hosts.length === 0 ? (
          <p className="mt-2 text-sm text-muted-foreground">
            {t("detail.network.noHosts")}
          </p>
        ) : (
          <>
            <p className="mt-2 text-sm text-muted-foreground">
              {t("detail.network.intro")}
            </p>
            <ul className="mt-2 flex flex-wrap gap-2">
              {d.allowed_hosts.map((h) => (
                <li key={h}>
                  <code className="rounded bg-muted px-2 py-1 font-mono text-xs">
                    {h}
                  </code>
                </li>
              ))}
            </ul>
          </>
        )}
        <p className="mt-3 text-xs text-muted-foreground">
          {t("detail.network.injectionNote")}
        </p>
      </section>

      {/* Available tools */}
      <section>
        <h2 className="mb-3 text-base font-semibold tracking-tight">
          {t("detail.tools.title", { count: d.tools.length })}
        </h2>
        {d.tools.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("detail.tools.empty")}</p>
        ) : (
          <ul className="flex flex-wrap gap-2">
            {d.tools.map((tool) => (
              <li key={tool.name}>
                <code className="rounded bg-muted px-2 py-1 font-mono text-xs">
                  {tool.name}
                </code>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Use in profiles */}
      <section>
        <h2 className="mb-3 text-base font-semibold tracking-tight">
          {t("detail.profiles.title")}
        </h2>
        {profiles.isLoading ? (
          <Skeleton className="h-12 w-full rounded-lg" />
        ) : (profiles.data ?? []).length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("detail.profiles.empty")}</p>
        ) : (
          <div className="space-y-2">
            {(profiles.data ?? []).map((p) => (
              <ProfileToggle key={p.id} profile={p} appName={d.name} />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
