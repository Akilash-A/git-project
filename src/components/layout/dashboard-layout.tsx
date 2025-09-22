
"use client";

import Link from "next/link";
import {
  Shield,
  Home,
  ListChecks,
  BarChart3,
  Settings,
  Archive,
  Brain,
} from "lucide-react";
import { usePathname } from "next/navigation";

import { cn } from "@/lib/utils";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  TooltipProvider,
} from "@/components/ui/tooltip";

export function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <TooltipProvider>
    <div className="flex min-h-screen w-full flex-col bg-muted/40">
      <aside className="fixed inset-y-0 left-0 z-10 hidden w-14 flex-col border-r bg-background sm:flex">
        <nav className="flex flex-col items-center gap-4 px-2 sm:py-5">
          <Link
            href="#"
            className="group flex h-9 w-9 shrink-0 items-center justify-center gap-2 rounded-full bg-primary text-lg font-semibold text-primary-foreground md:h-8 md:w-8 md:text-base"
          >
            <Shield className="h-4 w-4 transition-all group-hover:scale-110" />
            <span className="sr-only">NetGuardian</span>
          </Link>
          <Tooltip>
            <TooltipTrigger asChild>
              <Link
                href="/"
                className={cn("flex h-9 w-9 items-center justify-center rounded-lg transition-colors hover:text-foreground md:h-8 md:w-8",
                  pathname === "/" ? "bg-accent text-accent-foreground" : "text-muted-foreground"
                )}
              >
                <Home className="h-5 w-5" />
                <span className="sr-only">Dashboard</span>
              </Link>
            </TooltipTrigger>
            <TooltipContent side="right">Dashboard</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Link
                href="/whitelist"
                className={cn("flex h-9 w-9 items-center justify-center rounded-lg transition-colors hover:text-foreground md:h-8 md:w-8",
                  pathname === "/whitelist" ? "bg-accent text-accent-foreground" : "text-muted-foreground"
                )}
              >
                <ListChecks className="h-5 w-5" />
                <span className="sr-only">Whitelist</span>
              </Link>
            </TooltipTrigger>
            <TooltipContent side="right">Whitelist</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Link
                href="/packet-archive"
                className={cn("flex h-9 w-9 items-center justify-center rounded-lg transition-colors hover:text-foreground md:h-8 md:w-8",
                  pathname === "/packet-archive" ? "bg-accent text-accent-foreground" : "text-muted-foreground"
                )}
              >
                <Archive className="h-5 w-5" />
                <span className="sr-only">Packet Archive</span>
              </Link>
            </TooltipTrigger>
            <TooltipContent side="right">Packet Archive</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Link
                href="/ip-intelligence"
                className={cn("flex h-9 w-9 items-center justify-center rounded-lg transition-colors hover:text-foreground md:h-8 md:w-8",
                  pathname === "/ip-intelligence" ? "bg-accent text-accent-foreground" : "text-muted-foreground"
                )}
              >
                <Brain className="h-5 w-5" />
                <span className="sr-only">IP Intelligence</span>
              </Link>
            </TooltipTrigger>
            <TooltipContent side="right">IP Intelligence</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Link
                href="/security-analysis"
                className={cn("flex h-9 w-9 items-center justify-center rounded-lg transition-colors hover:text-foreground md:h-8 md:w-8",
                  pathname === "/security-analysis" ? "bg-accent text-accent-foreground" : "text-muted-foreground"
                )}
              >
                <BarChart3 className="h-5 w-5" />
                <span className="sr-only">Security Analysis</span>
              </Link>
            </TooltipTrigger>
            <TooltipContent side="right">Security Analysis</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Link
                href="/settings"
                className={cn("flex h-9 w-9 items-center justify-center rounded-lg transition-colors hover:text-foreground md:h-8 md:w-8",
                  pathname === "/settings" ? "bg-accent text-accent-foreground" : "text-muted-foreground"
                )}
              >
                <Settings className="h-5 w-5" />
                <span className="sr-only">Settings</span>
              </Link>
            </TooltipTrigger>
            <TooltipContent side="right">Settings</TooltipContent>
          </Tooltip>
        </nav>
      </aside>
      <div className="flex flex-col sm:gap-4 sm:py-4 sm:pl-14">
        {children}
      </div>
    </div>
    </TooltipProvider>
  );
}
