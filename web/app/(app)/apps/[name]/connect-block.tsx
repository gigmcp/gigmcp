"use client";
import { useState } from "react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";
import { CheckCircle2, KeyRound } from "lucide-react";
import { usePutCredential, useReadOnly } from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import type { AppDetail, CredentialPutBody } from "@/lib/types";
import { OAuthConnectBlock } from "./oauth-connect-block";

const textareaClass =
  "min-h-20 w-full min-w-0 resize-none rounded-md border border-input bg-background px-3 py-2 font-mono text-sm text-foreground transition-colors duration-150 ease-out outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/30 disabled:pointer-events-none disabled:cursor-not-allowed disabled:bg-muted disabled:opacity-50";

/** Builds the credential PUT body from the manifest inject spec + the secret. */
function buildBody(app: AppDetail, secret: string): CredentialPutBody {
  const body: CredentialPutBody = { secret };
  if (app.inject_header) body.inject_header = app.inject_header;
  if (app.inject_format) body.inject_format = app.inject_format;
  if (app.placeholder) body.placeholder = app.placeholder;
  if (app.allowed_hosts.length > 0) body.allowed_hosts = app.allowed_hosts;
  return body;
}

export function ConnectBlock({ app }: { app: AppDetail }) {
  const t = useTranslations("apps");
  const readOnly = useReadOnly();
  const put = usePutCredential();
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);

  if (app.auth_type === "none") {
    return (
      <section className="rounded-xl border border-border p-4">
        <h2 className="text-base font-semibold tracking-tight">
          {t("detail.connect.noSetupTitle")}
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">
          {t("detail.connect.noSetupDescription")}
        </p>
      </section>
    );
  }

  if (app.auth_type === "oauth2") {
    return (
      <section className="rounded-xl border border-border p-4">
        <h2 className="mb-3 text-base font-semibold tracking-tight">
          {t("detail.connect.oauthTitle")}
        </h2>
        <OAuthConnectBlock
          vendor={app.vendor}
          server={app.name}
          requiredScopes={app.scopes}
        />
      </section>
    );
  }

  // api_key | basic | custom_env → secret form.
  if (app.connected) {
    return (
      <section className="flex items-center gap-2 rounded-xl border border-border p-4">
        <CheckCircle2 className="size-5 text-[var(--color-success)]" aria-hidden />
        <span className="text-sm font-medium">{t("detail.connect.connected")}</span>
      </section>
    );
  }

  function handleSave() {
    if (!secret.trim()) return;
    setError(null);
    put.mutate(
      { server: app.name, body: buildBody(app, secret) },
      {
        onSuccess: () => {
          toast.success(t("detail.connect.saved", { name: app.display_name }));
          setSecret("");
        },
        onError: (err) => {
          setError(
            err instanceof ApiError ? err.message : t("detail.connect.saveFailed"),
          );
        },
      },
    );
  }

  return (
    <section className="rounded-xl border border-border p-4">
      <div className="flex items-center gap-2">
        <KeyRound className="size-4 text-muted-foreground" aria-hidden />
        <h2 className="text-base font-semibold tracking-tight">
          {t("detail.connect.title")}
        </h2>
      </div>
      <p className="mt-1 text-sm text-muted-foreground">
        {t("detail.connect.apiKeyDescription")}
      </p>
      <div className="mt-3 space-y-2">
        <Label htmlFor="connect-secret">{t("detail.connect.secretLabel")}</Label>
        <textarea
          id="connect-secret"
          className={textareaClass}
          placeholder={t("detail.connect.secretPlaceholder")}
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          autoComplete="off"
          spellCheck={false}
          disabled={readOnly}
        />
        {error && <p className="text-sm text-destructive">{error}</p>}
        <Button
          onClick={handleSave}
          disabled={put.isPending || readOnly || !secret.trim()}
        >
          {put.isPending ? t("detail.connect.saving") : t("detail.connect.save")}
        </Button>
      </div>
    </section>
  );
}
