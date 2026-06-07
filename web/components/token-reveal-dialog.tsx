"use client";
import { useState } from "react";
import { toast } from "sonner";
import { useTranslations } from "next-intl";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

interface TokenRevealDialogProps {
  open: boolean;
  token: string;
  onClose: () => void;
}

export function TokenRevealDialog({
  open,
  token,
  onClose,
}: TokenRevealDialogProps) {
  const t = useTranslations("common");
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    navigator.clipboard.writeText(token).then(() => {
      setCopied(true);
      toast.success(t("token.copiedToast"));
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>{t("token.title")}</DialogTitle>
          <DialogDescription>
            {t.rich("token.description", {
              strong: (chunks) => (
                <strong className="font-medium text-foreground">
                  {chunks}
                </strong>
              ),
            })}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <pre className="overflow-x-auto rounded-md border border-border bg-muted px-3 py-2 font-mono text-xs break-all whitespace-pre-wrap">
            {token}
          </pre>
          <Button variant="outline" size="sm" onClick={handleCopy}>
            {copied ? t("token.copied") : t("token.copy")}
          </Button>
        </div>
        <DialogFooter>
          <Button onClick={onClose}>{t("token.confirm")}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
