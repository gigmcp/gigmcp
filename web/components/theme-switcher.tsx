"use client";
import { useSyncExternalStore } from "react";
import { useTheme } from "next-themes";
import { useTranslations } from "next-intl";
import { Monitor, Sun, Moon } from "lucide-react";
import { cn } from "@/lib/utils";

const subscribeNoop = () => () => {};

const OPTIONS = [
  { value: "system", icon: Monitor, key: "system" },
  { value: "light", icon: Sun, key: "light" },
  { value: "dark", icon: Moon, key: "dark" },
] as const;

/**
 * Vercel-style segmented theme control: three icon buttons (monitor/sun/moon)
 * in a pill, the active one gets a bordered background.
 */
export function ThemeSwitcher({ className }: { className?: string }) {
  const t = useTranslations("common");
  const { theme, setTheme } = useTheme();
  // next-themes' theme is undefined on the server; render a neutral shell
  // for SSR/hydration, then show the active segment on the client.
  const mounted = useSyncExternalStore(
    subscribeNoop,
    () => true,
    () => false,
  );

  return (
    <div
      role="radiogroup"
      aria-label={t("theme.label")}
      className={cn(
        "inline-flex items-center gap-0.5 rounded-full border border-border bg-background p-0.5",
        className,
      )}
    >
      {OPTIONS.map((opt) => {
        const active = mounted && theme === opt.value;
        return (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={active}
            aria-label={t(`theme.${opt.key}`)}
            onClick={() => setTheme(opt.value)}
            className={cn(
              "flex size-6 items-center justify-center rounded-full text-muted-foreground transition-colors duration-150 ease-out hover:text-foreground",
              active && "bg-accent text-foreground shadow-none",
            )}
          >
            <opt.icon className="size-3.5" />
          </button>
        );
      })}
    </div>
  );
}
