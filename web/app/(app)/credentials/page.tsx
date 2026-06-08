"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";

// Renamed: Credentials → Connected Accounts.
export default function CredentialsRedirect() {
  const router = useRouter();
  useEffect(() => {
    router.replace("/connected-accounts");
  }, [router]);
  return null;
}
