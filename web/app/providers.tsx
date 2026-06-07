"use client";
import {
  QueryClient,
  QueryClientProvider,
  MutationCache,
  QueryCache,
} from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Toaster } from "@/components/ui/sonner";
import { toast } from "sonner";
import { ApiError } from "@/lib/api";

export function Providers({ children }: { children: React.ReactNode }) {
  const router = useRouter();
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
      toast.error("Unexpected error");
    };
    return new QueryClient({
      queryCache: new QueryCache({ onError }),
      mutationCache: new MutationCache({ onError }),
      defaultOptions: { queries: { staleTime: 10_000, retry: false } },
    });
  });
  return (
    <QueryClientProvider client={client}>
      {children}
      <Toaster richColors position="top-right" />
    </QueryClientProvider>
  );
}
