"use client";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert } from "@/components/ui/alert";
import { api, ApiError } from "@/lib/api";

export default function LoginPage() {
  const [disabled, setDisabled] = useState<string | null>(null);
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    // Call api.me() directly (not via useQuery) to avoid the global QueryCache
    // 401 handler firing a spurious redirect to /login while we're already here.
    // • 200 → already signed in, go home
    // • 404 control_plane_disabled → show setup hint
    // • 401 unauthenticated → show the login button (normal case)
    // • any other error → show the login button (best effort)
    api
      .me()
      .then(() => {
        window.location.href = "/";
      })
      .catch((e) => {
        if (e instanceof ApiError && e.code === "control_plane_disabled") {
          setDisabled(e.message);
        }
        // 401 or anything else: just show the login button
      })
      .finally(() => setChecked(true));
  }, []);

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-6">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="text-center">Sign in to gigmcp</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {disabled ? (
            <Alert variant="destructive">
              <p className="text-sm font-medium">Control plane not configured</p>
              <p className="mt-1 text-sm">{disabled}</p>
            </Alert>
          ) : (
            <Button
              className="w-full"
              disabled={!checked}
              onClick={() => {
                // Full-page navigation — NOT fetch. The browser must follow the
                // 302 → Zitadel → callback (Set-Cookie) → 302 / chain itself.
                window.location.href = "/api/auth/login";
              }}
            >
              Continue with Zitadel
            </Button>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
