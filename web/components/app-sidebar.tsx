"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslations } from "next-intl";
import {
  LayoutDashboard,
  Grid3x3,
  Layers,
  Plug,
  Users,
  ScrollText,
  LogOut,
  KeyRound,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Logo } from "@/components/logo";
import { Button } from "@/components/ui/button";
import { ThemeSwitcher } from "@/components/theme-switcher";
import { LanguageSwitcher } from "@/components/language-switcher";
import { api } from "@/lib/api";
import { useRouter } from "next/navigation";
import type { User } from "@/lib/types";

const NAV = [
  { href: "/", key: "overview", icon: LayoutDashboard, admin: false },
  { href: "/apps", key: "apps", icon: Grid3x3, admin: false },
  { href: "/profiles", key: "profiles", icon: Layers, admin: false },
  { href: "/connected-accounts", key: "connectedAccounts", icon: Plug, admin: false },
  { href: "/users", key: "users", icon: Users, admin: true },
  { href: "/auth-configs", key: "authConfigs", icon: KeyRound, admin: true },
  { href: "/audit", key: "audit", icon: ScrollText, admin: false },
] as const;

export function AppSidebar({
  role,
  user,
}: {
  role: "admin" | "user";
  user?: User;
}) {
  const t = useTranslations("common");
  const pathname = usePathname();
  const router = useRouter();
  const items = NAV.filter((n) => !n.admin || role === "admin");
  return (
    <aside className="flex h-screen w-60 shrink-0 flex-col border-r border-sidebar-border bg-sidebar">
      <div className="flex items-center gap-2 px-6 py-5 text-sm font-semibold tracking-tight">
        <Logo className="h-4 w-auto" />
        Gig&apos;MCP
      </div>
      <nav className="flex-1 space-y-0.5 px-3">
        {items.map((n) => {
          const active =
            n.href === "/" ? pathname === "/" : pathname.startsWith(n.href);
          return (
            <Link
              key={n.href}
              href={n.href}
              className={cn(
                "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors duration-150 ease-out hover:bg-accent hover:text-foreground",
                active && "bg-accent font-medium text-foreground",
              )}
            >
              <n.icon className="size-4" />
              {t(`nav.${n.key}`)}
            </Link>
          );
        })}
      </nav>
      <div className="space-y-3 border-t border-sidebar-border p-4">
        {user && (
          <div className="min-w-0 px-1">
            <div className="truncate text-sm font-medium text-foreground">
              {user.display_name || user.email}
            </div>
            <div className="truncate font-mono text-xs text-muted-foreground">
              {user.email}
            </div>
          </div>
        )}
        <div className="flex items-center justify-between gap-2">
          <LanguageSwitcher className="min-w-0 text-muted-foreground" />
          <ThemeSwitcher />
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="w-full justify-start gap-2.5 text-muted-foreground"
          onClick={async () => {
            await api.logout();
            router.replace("/login");
          }}
        >
          <LogOut className="size-4" />
          {t("signOut")}
        </Button>
      </div>
    </aside>
  );
}
