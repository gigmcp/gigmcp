"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Boxes,
  Layers,
  KeyRound,
  Users,
  ScrollText,
  LogOut,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { useRouter } from "next/navigation";

const NAV = [
  { href: "/", label: "Overview", icon: LayoutDashboard, admin: false },
  { href: "/servers", label: "Servers", icon: Boxes, admin: false },
  { href: "/profiles", label: "Profiles", icon: Layers, admin: false },
  { href: "/credentials", label: "Credentials", icon: KeyRound, admin: false },
  { href: "/users", label: "Users", icon: Users, admin: true },
  { href: "/audit", label: "Audit", icon: ScrollText, admin: false },
];

export function AppSidebar({ role }: { role: "admin" | "user" }) {
  const pathname = usePathname();
  const router = useRouter();
  const items = NAV.filter((n) => !n.admin || role === "admin");
  return (
    <aside className="flex h-screen w-60 shrink-0 flex-col border-r border-border bg-card">
      <div className="px-5 py-5 text-lg font-semibold tracking-tight">gigmcp</div>
      <nav className="flex-1 space-y-1 px-3">
        {items.map((n) => {
          const active =
            n.href === "/" ? pathname === "/" : pathname.startsWith(n.href);
          return (
            <Link
              key={n.href}
              href={n.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground",
                active && "bg-accent text-foreground",
              )}
            >
              <n.icon className="h-4 w-4" />
              {n.label}
            </Link>
          );
        })}
      </nav>
      <div className="border-t border-border p-3">
        <Button
          variant="ghost"
          className="w-full justify-start gap-3 text-muted-foreground"
          onClick={async () => {
            await api.logout();
            router.replace("/login");
          }}
        >
          <LogOut className="h-4 w-4" />
          Sign out
        </Button>
      </div>
    </aside>
  );
}
