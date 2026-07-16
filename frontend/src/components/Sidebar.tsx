"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, LayoutDashboard, Scan, Bug, GitBranch, FileBarChart, Settings } from "lucide-react";
import { clsx } from "clsx";

const NAV = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/scans", label: "Scans", icon: Scan },
  { href: "/findings", label: "Findings", icon: Bug },
  { href: "/repositories", label: "Repositories", icon: GitBranch },
  { href: "/reports", label: "Reports", icon: FileBarChart },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  return (
    <aside className="sticky top-0 flex h-screen w-56 flex-col border-r border-border bg-bg-soft">
      <div className="flex items-center gap-2 px-5 py-5">
        <Shield className="h-6 w-6 text-accent" />
        <span className="text-lg font-bold tracking-tight">VIGIL</span>
      </div>
      <nav className="flex-1 px-2 py-2">
        {NAV.map((item) => {
          const active = pathname === item.href || pathname?.startsWith(item.href + "/");
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={clsx(
                "mb-0.5 flex items-center gap-3 rounded-md px-3 py-2 text-sm transition",
                active ? "bg-accent/10 text-accent" : "text-gray-400 hover:bg-bg-card hover:text-gray-200",
              )}
            >
              <Icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="border-t border-border px-5 py-3 text-xs text-gray-500">
        v0.1.0 · open source
      </div>
    </aside>
  );
}
