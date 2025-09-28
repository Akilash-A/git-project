import { ListChecks } from "lucide-react";
import { WhitelistManager } from "@/components/whitelist/whitelist-manager";
import { DashboardLayout } from "@/components/layout/dashboard-layout";

export default function WhitelistPage() {
  return (
    <DashboardLayout>
      <main className="flex flex-1 flex-col gap-4 p-4 md:gap-8 md:p-8">
        <div className="flex items-center gap-2">
          <ListChecks className="h-6 w-6" />
          <h1 className="font-headline text-lg font-semibold md:text-2xl">
            IP Whitelist
          </h1>
        </div>
        <WhitelistManager />
      </main>
    </DashboardLayout>
  );
}
