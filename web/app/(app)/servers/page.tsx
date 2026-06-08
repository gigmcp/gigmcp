"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";

// Renamed: Servers → Apps. Kept as a client redirect in addition to the
// next.config.ts redirect so a soft client-side navigation also lands on /apps.
export default function ServersRedirect() {
  const router = useRouter();
  useEffect(() => {
    router.replace("/apps");
  }, [router]);
  return null;
}
