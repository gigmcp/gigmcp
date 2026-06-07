"use client";
import { useTranslations } from "next-intl";
import { Button } from "@/components/ui/button";
import { useStopImpersonation } from "@/lib/queries";
import type { Me } from "@/lib/types";

export function ImpersonationBanner({ me }: { me: Me }) {
  const t = useTranslations("common");
  const stop = useStopImpersonation();
  if (!me.impersonating || !me.real_user) return null;
  return (
    <div className="flex items-center justify-between gap-4 border-b border-warning/30 bg-warning/10 px-6 py-1.5 text-sm text-foreground">
      <span className="truncate">
        {t.rich("impersonation.viewingAs", {
          user: me.user.email,
          realUser: me.real_user.email,
          strong: (chunks) => <strong className="font-medium">{chunks}</strong>,
        })}
      </span>
      <Button
        size="sm"
        variant="outline"
        className="shrink-0"
        disabled={stop.isPending}
        onClick={() => stop.mutate()}
      >
        {t("impersonation.stop")}
      </Button>
    </div>
  );
}
