"use client";
import { useState } from "react";
import Link from "next/link";
import { toast } from "sonner";
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

const READ_ONLY_TITLE = "Read-only while viewing as another user";

function CreateProfileDialog({ disabled }: { disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [revealToken, setRevealToken] = useState<string | null>(null);

  const create = useCreateProfile();

  function handleOpen(o: boolean) {
    setOpen(o);
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
          setOpen(false);
          setName("");
          setSlug("");
          if (profile.token) {
            setRevealToken(profile.token);
          } else {
            toast.success(`Profile "${profile.name}" created`);
          }
        },
        onError: (err) => {
          if (err instanceof ApiError) {
            if (err.code === "conflict") {
              setError("Slug is already taken. Please choose a different slug.");
            } else {
              setError(err.message);
            }
          } else {
            setError("Failed to create profile");
          }
        },
      },
    );
  }

  const trigger = (
    <Button onClick={() => setOpen(true)} disabled={disabled}>
      Create profile
    </Button>
  );

  return (
    <>
      {disabled ? (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger>
              <span tabIndex={0}>{trigger}</span>
            </TooltipTrigger>
            <TooltipContent>{READ_ONLY_TITLE}</TooltipContent>
          </Tooltip>
        </TooltipProvider>
      ) : (
        trigger
      )}

      <Dialog open={open} onOpenChange={handleOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create profile</DialogTitle>
            <DialogDescription>
              A profile provides an MCP endpoint with a curated set of servers.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="profile-name">Name</Label>
              <Input
                id="profile-name"
                placeholder="My profile"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="profile-slug">Slug</Label>
              <Input
                id="profile-slug"
                placeholder="my-profile"
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleCreate();
                }}
              />
              <p className="text-xs text-muted-foreground">
                Lowercase letters, digits, and hyphens (2–63 chars, must start
                with a letter/digit).
              </p>
            </div>
            {error && (
              <p className="text-sm text-destructive">{error}</p>
            )}
          </div>
          <DialogFooter>
            <Button
              onClick={handleCreate}
              disabled={
                create.isPending || !name.trim() || !slug.trim()
              }
            >
              {create.isPending ? "Creating…" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <TokenRevealDialog
        open={!!revealToken}
        token={revealToken ?? ""}
        onClose={() => setRevealToken(null)}
      />
    </>
  );
}

export default function ProfilesPage() {
  const profiles = useProfiles();
  const readOnly = useReadOnly();

  const columns: Column<Profile>[] = [
    {
      header: "Name",
      cell: (p) => (
        <Link
          href={`/profiles/${p.id}`}
          className="font-medium underline-offset-4 hover:underline"
        >
          {p.name}
        </Link>
      ),
    },
    { header: "Slug", cell: (p) => p.slug },
    {
      header: "Endpoint",
      cell: (p) => (
        <span className="font-mono text-xs text-muted-foreground">
          {p.endpoint}
        </span>
      ),
    },
    {
      header: "Servers",
      cell: (p) => p.servers.length,
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Profiles</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            MCP endpoint profiles with bundled server sets.
          </p>
        </div>
        <CreateProfileDialog disabled={readOnly} />
      </div>

      {profiles.isLoading ? (
        <div className="space-y-2">
          {[...Array(3)].map((_, i) => (
            <Skeleton key={i} className="h-10 w-full rounded-md" />
          ))}
        </div>
      ) : profiles.data && profiles.data.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted-foreground">
          No profiles yet. Create one to get started.
        </p>
      ) : (
        <DataTable
          columns={columns}
          data={profiles.data ?? []}
          getKey={(p) => p.id}
        />
      )}
    </div>
  );
}
