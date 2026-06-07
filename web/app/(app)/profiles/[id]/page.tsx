"use client";
import { useState } from "react";
import { useParams } from "next/navigation";
import { useTranslations } from "next-intl";
import { useProfile, useReadOnly } from "@/lib/queries";
import { TokenRevealDialog } from "@/components/token-reveal-dialog";
import { Skeleton } from "@/components/ui/skeleton";
import type { Profile } from "@/lib/types";
import { BundleCard } from "./bundle-card";
import {
  DeleteCard,
  EndpointCard,
  RenameCard,
  RotateTokenCard,
} from "./sections";

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
  const [revealToken, setRevealToken] = useState<string | null>(null);

  // Derive endpoint URL at render time.
  const endpoint =
    typeof window !== "undefined"
      ? `${window.location.origin}${p.endpoint}`
      : p.endpoint;

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

      <EndpointCard endpoint={endpoint} />

      <BundleCard
        profileId={p.id}
        initialServers={initialServers}
        readOnly={readOnly}
      />

      <RenameCard profile={p} initialName={initialName} readOnly={readOnly} />

      <RotateTokenCard
        profileId={p.id}
        readOnly={readOnly}
        onReveal={setRevealToken}
      />

      <DeleteCard profile={p} readOnly={readOnly} />

      <TokenRevealDialog
        open={!!revealToken}
        token={revealToken ?? ""}
        onClose={() => setRevealToken(null)}
      />
    </div>
  );
}

function ProfileDetailSkeleton() {
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

export default function ProfileDetailPage() {
  const t = useTranslations("profiles");
  const params = useParams();
  const id = Number(params.id);
  const profile = useProfile(id);
  const readOnly = useReadOnly();

  if (profile.isLoading) {
    return <ProfileDetailSkeleton />;
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
