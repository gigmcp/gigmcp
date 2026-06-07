"use client";
import { useEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { api, ApiError } from "@/lib/api";
import { Logo } from "@/components/logo";

export default function LoginPage() {
  const t = useTranslations("login");
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
      <div className="w-full max-w-sm space-y-6">
        <div className="flex flex-col items-center gap-3">
          <Logo className="h-8 w-auto" />
          <div className="text-center text-lg font-semibold tracking-tight">
            {t("wordmark")}
          </div>
        </div>
        <Card>
          <CardHeader className="justify-items-center text-center">
            <CardTitle>{t("title")}</CardTitle>
            <CardDescription>{t("description")}</CardDescription>
          </CardHeader>
          <CardContent>
            {disabled ? (
              <Alert variant="destructive">
                <AlertTitle>{t("controlPlaneDisabled")}</AlertTitle>
                <AlertDescription>{disabled}</AlertDescription>
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
                {t("continueWithZitadel")}
              </Button>
            )}
          </CardContent>
        </Card>
        {!disabled && (
          <p className="text-center text-xs text-muted-foreground">
            {t("redirectNotice")}
          </p>
        )}
      </div>
    </div>
  );
}
