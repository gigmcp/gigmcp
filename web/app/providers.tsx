"use client";
import {
  QueryClient,
  QueryClientProvider,
  MutationCache,
  QueryCache,
} from "@tanstack/react-query";
import { ThemeProvider } from "next-themes";
import { useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Toaster } from "@/components/ui/sonner";
import { toast } from "sonner";
import { ApiError } from "@/lib/api";

// Module-scoped holder so the long-lived QueryClient closure always sees the
// current locale's message (Providers is a singleton; locale switches use
// router.refresh(), which re-renders without recreating the QueryClient).
let unexpectedErrorMessage = "Something went wrong";

export function Providers({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const t = useTranslations("common");
  const translatedError = t("error");
  useEffect(() => {
    unexpectedErrorMessage = translatedError;
  }, [translatedError]);
  const [client] = useState(() => {
    const onError = (err: unknown) => {
      if (err instanceof ApiError) {
        // Session gone (or control plane disabled probed via /api/me): bounce.
        if (err.status === 401) {
          router.replace("/login");
          return;
        }
        toast.error(err.message);
        return;
      }
      toast.error(unexpectedErrorMessage);
    };
    return new QueryClient({
      queryCache: new QueryCache({ onError }),
      mutationCache: new MutationCache({ onError }),
      defaultOptions: { queries: { staleTime: 10_000, retry: false } },
    });
  });
  return (
    <ThemeProvider
      attribute="class"
      defaultTheme="system"
      enableSystem
      disableTransitionOnChange
    >
      <QueryClientProvider client={client}>
        {children}
        <Toaster richColors position="top-right" />
      </QueryClientProvider>
    </ThemeProvider>
  );
}
