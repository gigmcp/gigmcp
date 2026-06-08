"use client";
import { useState } from "react";
import { toast } from "sonner";
import { useTranslations } from "next-intl";
import { useServers, useSetProfileServers } from "@/lib/queries";
import { Checkbox } from "@/components/ui/checkbox";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { Profile, Server } from "@/lib/types";
import { ReadOnlyTooltip, toastMutationError } from "./sections";

function ServerChecklist({
  servers,
  selectedServers,
  readOnly,
  onToggle,
}: {
  servers: Server[];
  selectedServers: Set<string>;
  readOnly: boolean;
  onToggle: (name: string, checked: boolean) => void;
}) {
  return (
    <div className="space-y-2">
      {servers.map((s) => (
        <label
          key={s.name}
          className={[
            "flex cursor-pointer items-center gap-3",
            readOnly ? "opacity-60 cursor-not-allowed" : "",
          ].join(" ")}
        >
          <Checkbox
            checked={selectedServers.has(s.name)}
            disabled={readOnly}
            onCheckedChange={(checked) =>
              !readOnly && onToggle(s.name, checked as boolean)
            }
          />
          <span className="font-mono text-[13px]">{s.name}</span>
        </label>
      ))}
    </div>
  );
}

function BundleCardBody({
  isLoading,
  serverList,
  selectedServers,
  readOnly,
  onToggle,
}: {
  isLoading: boolean;
  serverList: Server[];
  selectedServers: Set<string>;
  readOnly: boolean;
  onToggle: (name: string, checked: boolean) => void;
}) {
  const t = useTranslations("profiles");

  if (isLoading) {
    return (
      <div className="space-y-2">
        {[...Array(3)].map((_, i) => (
          <Skeleton key={i} className="h-6 w-48 rounded" />
        ))}
      </div>
    );
  }

  if (serverList.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        {t("detail.bundle.noServers")}
      </p>
    );
  }

  return (
    <ServerChecklist
      servers={serverList}
      selectedServers={selectedServers}
      readOnly={readOnly}
      onToggle={onToggle}
    />
  );
}

export function BundleCard({
  profileId,
  initialServers,
  readOnly,
}: {
  profileId: Profile["id"];
  initialServers: Set<string>;
  readOnly: boolean;
}) {
  const t = useTranslations("profiles");
  const servers = useServers();
  const setServersMut = useSetProfileServers();
  const [selectedServers, setSelectedServers] =
    useState<Set<string>>(initialServers);
  const serverList = servers.data ?? [];

  function toggleServer(name: string, checked: boolean) {
    setSelectedServers((prev) => {
      const next = new Set(prev);
      if (checked) next.add(name);
      else next.delete(name);
      return next;
    });
  }

  function handleSaveBundle() {
    setServersMut.mutate(
      { id: profileId, servers: Array.from(selectedServers) },
      {
        onSuccess: () => toast.success(t("detail.bundle.savedToast")),
        onError: (err) => toastMutationError(err, t("detail.bundle.saveFailed")),
      },
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("detail.bundle.title")}</CardTitle>
        <CardDescription>{t("detail.bundle.description")}</CardDescription>
      </CardHeader>
      <CardContent>
        <BundleCardBody
          isLoading={servers.isLoading}
          serverList={serverList}
          selectedServers={selectedServers}
          readOnly={readOnly}
          onToggle={toggleServer}
        />
      </CardContent>
      {serverList.length > 0 && (
        <CardFooter className="justify-end">
          <ReadOnlyTooltip readOnly={readOnly}>
            <Button
              onClick={handleSaveBundle}
              disabled={setServersMut.isPending || readOnly}
              size="sm"
            >
              {setServersMut.isPending
                ? t("detail.bundle.saving")
                : t("detail.bundle.save")}
            </Button>
          </ReadOnlyTooltip>
        </CardFooter>
      )}
    </Card>
  );
}
