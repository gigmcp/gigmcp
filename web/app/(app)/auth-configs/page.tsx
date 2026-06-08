"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { useAuthConfigs, usePutAuthConfig, useDeleteAuthConfig, useReadOnly } from "@/lib/queries";
import type { AuthConfigPutBody } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

const EMPTY: AuthConfigPutBody = {
  authorize_url: "",
  token_url: "",
  client_id: "",
  client_secret: "",
  default_scopes: [],
  pkce: true,
  mode: "byo",
};

export default function AuthConfigsPage() {
  const t = useTranslations("authConfigs");
  const { data: configs, isLoading } = useAuthConfigs();
  const put = usePutAuthConfig();
  const del = useDeleteAuthConfig();
  const readOnly = useReadOnly();

  const [vendor, setVendor] = useState("");
  const [form, setForm] = useState<AuthConfigPutBody>(EMPTY);

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!vendor) return;
    put.mutate(
      { vendor, body: form },
      { onSuccess: () => { setVendor(""); setForm(EMPTY); } },
    );
  };

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">{t("title")}</h1>
        <p className="text-sm text-muted-foreground">{t("subtitle")}</p>
      </header>

      <form onSubmit={onSubmit} autoComplete="off" className="grid grid-cols-2 gap-3 rounded-lg border border-border p-4">
        <Input placeholder={t("vendor")} value={vendor} onChange={(e) => setVendor(e.target.value)} />
        <select
          className="rounded-md border border-border bg-background px-3 text-sm"
          value={form.mode}
          onChange={(e) => setForm({ ...form, mode: e.target.value as "managed" | "byo" })}
        >
          <option value="byo">{t("modeByo")}</option>
          <option value="managed">{t("modeManaged")}</option>
        </select>
        <Input placeholder={t("authorizeUrl")} value={form.authorize_url} onChange={(e) => setForm({ ...form, authorize_url: e.target.value })} />
        <Input placeholder={t("tokenUrl")} value={form.token_url} onChange={(e) => setForm({ ...form, token_url: e.target.value })} />
        <Input name="oauth_client_id" id="oauth_client_id" autoComplete="off" placeholder={t("clientId")} value={form.client_id} onChange={(e) => setForm({ ...form, client_id: e.target.value })} />
        <Input name="oauth_client_secret" id="oauth_client_secret" type="password" autoComplete="new-password" placeholder={t("clientSecret")} value={form.client_secret ?? ""} onChange={(e) => setForm({ ...form, client_secret: e.target.value })} />
        <Input
          placeholder={t("defaultScopes")}
          value={(form.default_scopes ?? []).join(" ")}
          onChange={(e) => setForm({ ...form, default_scopes: e.target.value.split(/\s+/).filter(Boolean) })}
        />
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={form.pkce ?? false} onChange={(e) => setForm({ ...form, pkce: e.target.checked })} />
          {t("pkce")}
        </label>
        <div className="col-span-2">
          <Button type="submit" disabled={readOnly || put.isPending}>{t("save")}</Button>
        </div>
      </form>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">{t("loading")}</p>
      ) : (
        <ul className="divide-y divide-border rounded-lg border border-border">
          {(configs ?? []).map((c) => (
            <li key={c.vendor} className="flex items-center justify-between p-4">
              <div>
                <p className="font-medium">{c.vendor}</p>
                <p className="text-xs text-muted-foreground">
                  {c.mode} · {c.client_id} · {c.has_secret ? t("secretSet") : t("secretMissing")}
                </p>
              </div>
              <Button variant="destructive" size="sm" disabled={readOnly} onClick={() => del.mutate(c.vendor)}>
                {t("delete")}
              </Button>
            </li>
          ))}
          {(configs ?? []).length === 0 && <li className="p-4 text-sm text-muted-foreground">{t("empty")}</li>}
        </ul>
      )}
    </div>
  );
}
