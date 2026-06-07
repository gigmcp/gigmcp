"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useMe } from "@/lib/queries";
import { AppSidebar } from "@/components/app-sidebar";
import { ImpersonationBanner } from "@/components/impersonation-banner";
import { Skeleton } from "@/components/ui/skeleton";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const me = useMe();
  const router = useRouter();

  // Bounce to /login on ANY error from /api/me — including:
  //   • 401 unauthenticated (no/expired session)
  //   • 404 control_plane_disabled (OIDC not configured)
  //   • network / other failures
  // The /login page is the single place that renders the setup hint for the
  // disabled-state case. The global Providers error handler also catches 401s
  // from other queries, but this gate must not depend solely on that path.
  useEffect(() => {
    if (me.isError) {
      router.replace("/login");
    }
  }, [me.isError, router]);

  if (me.isLoading) {
    return (
      <div className="flex h-screen">
        <Skeleton className="h-screen w-60" />
        <div className="flex-1 p-8">
          <Skeleton className="h-8 w-48" />
        </div>
      </div>
    );
  }
  if (!me.data) return null; // redirect in flight (error path above fires)
  return (
    <div className="flex h-screen overflow-hidden">
      <AppSidebar role={me.data.user.role} />
      <div className="flex flex-1 flex-col overflow-hidden">
        <ImpersonationBanner me={me.data} />
        <main className="flex-1 overflow-y-auto p-8">{children}</main>
      </div>
    </div>
  );
}
