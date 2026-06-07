"use client";
import { Button } from "@/components/ui/button";
import { useStopImpersonation } from "@/lib/queries";
import type { Me } from "@/lib/types";

export function ImpersonationBanner({ me }: { me: Me }) {
  const stop = useStopImpersonation();
  if (!me.impersonating || !me.real_user) return null;
  return (
    <div className="flex items-center justify-between gap-4 bg-amber-500/15 px-6 py-2 text-sm text-amber-200">
      <span>
        Viewing as <strong>{me.user.email}</strong> (you are{" "}
        {me.real_user.email}). All changes are blocked while impersonating.
      </span>
      <Button
        size="sm"
        variant="outline"
        disabled={stop.isPending}
        onClick={() => stop.mutate()}
      >
        Stop
      </Button>
    </div>
  );
}
