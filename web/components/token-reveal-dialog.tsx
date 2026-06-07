"use client";
import { useState } from "react";
import { toast } from "sonner";
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
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    navigator.clipboard.writeText(token).then(() => {
      setCopied(true);
      toast.success("Token copied to clipboard");
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>Your token</DialogTitle>
          <DialogDescription>
            Copy your token now. It will <strong>not</strong> be shown again.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <pre className="overflow-x-auto rounded-lg bg-muted px-3 py-2 font-mono text-xs break-all whitespace-pre-wrap">
            {token}
          </pre>
          <Button variant="outline" size="sm" onClick={handleCopy}>
            {copied ? "Copied!" : "Copy token"}
          </Button>
        </div>
        <DialogFooter>
          <Button onClick={onClose}>I have copied my token</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
