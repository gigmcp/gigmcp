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
    const onError = (err: unknown, meta?: Record<string, unknown>) => {
      if (err instanceof ApiError && err.status === 401) {
        // Session gone (or control plane disabled probed via /api/me): bounce.
        router.replace("/login");
        return;
      }
      // Queries that render their own error UI (e.g. the registry catalog's
      // in-dialog empty/retry states) opt out of the global toast.
      if (meta?.suppressErrorToast) return;
      toast.error(
        err instanceof ApiError ? err.message : unexpectedErrorMessage,
      );
    };
    return new QueryClient({
      queryCache: new QueryCache({
        onError: (err, query) => onError(err, query.meta),
      }),
      mutationCache: new MutationCache({
        onError: (err, _vars, _ctx, mutation) => onError(err, mutation.meta),
      }),
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
