"use client";
import { useRouter } from "next/navigation";
import { useLocale, useTranslations } from "next-intl";
import { useTransition } from "react";
import { Check, Globe } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { LOCALES, LOCALE_NAMES, isAppLocale } from "@/i18n/config";
import { setLocale } from "@/lib/locale";

/**
 * Language dropdown showing autonyms. Selecting a locale calls the
 * setLocale server action (writes the NEXT_LOCALE cookie — no app/api
 * routes allowed) and refreshes the tree so server-provided messages reload.
 */
export function LanguageSwitcher({ className }: { className?: string }) {
  const t = useTranslations("common");
  const locale = useLocale();
  const router = useRouter();
  const [, startTransition] = useTransition();

  const current = isAppLocale(locale) ? locale : "en";

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            variant="ghost"
            size="sm"
            aria-label={t("language.label")}
            className={className}
          />
        }
      >
        <Globe className="size-4" />
        {LOCALE_NAMES[current]}
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-40">
        {LOCALES.map((code) => (
          <DropdownMenuItem
            key={code}
            onClick={() => {
              startTransition(async () => {
                await setLocale(code);
                router.refresh();
              });
            }}
          >
            {LOCALE_NAMES[code]}
            {code === current && (
              <Check className="ml-auto size-4 text-muted-foreground" />
            )}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
