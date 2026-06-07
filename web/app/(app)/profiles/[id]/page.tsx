"use client";
import { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { toast } from "sonner";
import {
  useProfile,
  useServers,
  useSetProfileServers,
  useRenameProfile,
  useRotateToken,
  useDeleteProfile,
} from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { TokenRevealDialog } from "@/components/token-reveal-dialog";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import type { Profile } from "@/lib/types";

interface ProfileDetailProps {
  profile: Profile;
  initialName: string;
  initialServers: Set<string>;
}

// Inner component is keyed by profile id so React remounts it (and thus
// re-runs all useState initialisers) whenever navigation switches profile.
function ProfileDetail({
  profile: p,
  initialName,
  initialServers,
}: ProfileDetailProps) {
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
        onSuccess: () => toast.success("Bundle saved"),
        onError: (err) => {
          const msg = err instanceof ApiError ? err.message : "Save failed";
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
        onSuccess: () => toast.success("Profile renamed"),
        onError: (err) => {
          const msg = err instanceof ApiError ? err.message : "Rename failed";
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
          toast.success("Token rotated");
        }
      },
      onError: (err) => {
        const msg = err instanceof ApiError ? err.message : "Rotate failed";
        toast.error(msg);
      },
    });
  }

  function handleDelete() {
    deleteProfile.mutate(p.id, {
      onSuccess: () => {
        toast.success("Profile deleted");
        router.push("/profiles");
      },
      onError: (err) => {
        const msg = err instanceof ApiError ? err.message : "Delete failed";
        toast.error(msg);
      },
    });
  }

  function copyEndpoint() {
    navigator.clipboard.writeText(endpoint).then(() =>
      toast.success("Endpoint URL copied"),
    );
  }

  return (
    <div className="space-y-8 max-w-2xl">
      <div>
        <h1 className="text-2xl font-semibold">{p.name}</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Profile detail — slug: <span className="font-mono">{p.slug}</span>
        </p>
      </div>

      {/* Endpoint URL */}
      <section className="space-y-2">
        <h2 className="text-sm font-medium">Endpoint URL</h2>
        <div className="flex items-center gap-2">
          <code className="flex-1 overflow-x-auto rounded-lg bg-muted px-3 py-2 font-mono text-xs">
            {endpoint}
          </code>
          <Button variant="outline" size="sm" onClick={copyEndpoint}>
            Copy
          </Button>
        </div>
      </section>

      <Separator />

      {/* Bundle editor */}
      <section className="space-y-3">
        <h2 className="text-sm font-medium">Server bundle</h2>
        {servers.isLoading ? (
          <p className="text-sm text-muted-foreground">Loading servers…</p>
        ) : servers.data && servers.data.length > 0 ? (
          <div className="space-y-2">
            {servers.data.map((s) => (
              <label
                key={s.name}
                className="flex cursor-pointer items-center gap-3"
              >
                <Checkbox
                  checked={selectedServers.has(s.name)}
                  onCheckedChange={(checked) =>
                    toggleServer(s.name, checked as boolean)
                  }
                />
                <span className="text-sm">{s.name}</span>
              </label>
            ))}
            <div className="pt-2">
              <Button
                onClick={handleSaveBundle}
                disabled={setServersMut.isPending}
                size="sm"
              >
                {setServersMut.isPending ? "Saving…" : "Save bundle"}
              </Button>
            </div>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            No servers installed yet.
          </p>
        )}
      </section>

      <Separator />

      {/* Rename */}
      <section className="space-y-3">
        <h2 className="text-sm font-medium">Rename profile</h2>
        <div className="flex items-center gap-2">
          <div className="flex-1 space-y-1">
            <Label htmlFor="rename-input" className="sr-only">
              Profile name
            </Label>
            <Input
              id="rename-input"
              value={profileName}
              onChange={(e) => setProfileName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleRename();
              }}
            />
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={handleRename}
            disabled={
              rename.isPending ||
              !profileName.trim() ||
              profileName.trim() === p.name
            }
          >
            {rename.isPending ? "Saving…" : "Rename"}
          </Button>
        </div>
      </section>

      <Separator />

      {/* Token rotation */}
      <section className="space-y-3">
        <h2 className="text-sm font-medium">Rotate token</h2>
        <p className="text-sm text-muted-foreground">
          Generates a new token and immediately invalidates the previous one.
        </p>
        <Button
          variant="outline"
          onClick={handleRotateToken}
          disabled={rotateToken.isPending}
        >
          {rotateToken.isPending ? "Rotating…" : "Rotate token"}
        </Button>
      </section>

      <Separator />

      {/* Delete */}
      <section className="space-y-3">
        <h2 className="text-sm font-medium text-destructive">
          Delete profile
        </h2>
        <p className="text-sm text-muted-foreground">
          This is permanent. The endpoint will stop working immediately.
        </p>
        <ConfirmDialog
          trigger={
            <Button variant="destructive" disabled={deleteProfile.isPending}>
              Delete profile
            </Button>
          }
          title={`Delete "${p.name}"?`}
          description="This will permanently delete the profile and its endpoint. This action cannot be undone."
          confirmLabel="Delete"
          isPending={deleteProfile.isPending}
          onConfirm={handleDelete}
        />
      </section>

      <TokenRevealDialog
        open={!!revealToken}
        token={revealToken ?? ""}
        onClose={() => setRevealToken(null)}
      />
    </div>
  );
}

export default function ProfileDetailPage() {
  const params = useParams();
  const id = Number(params.id);
  const profile = useProfile(id);

  if (profile.isLoading) {
    return <p className="text-sm text-muted-foreground">Loading…</p>;
  }

  if (!profile.data) {
    return <p className="text-sm text-destructive">Profile not found.</p>;
  }

  const p = profile.data;

  return (
    <ProfileDetail
      key={p.id}
      profile={p}
      initialName={p.name}
      initialServers={new Set(p.servers)}
    />
  );
}
