import { Home as HomeIcon } from "lucide-react";
import { DashboardClient } from "@/components/dashboard/dashboard-client";
import { DashboardLayout } from "@/components/layout/dashboard-layout";

export default function Home() {
  return (
    <DashboardLayout>
      <div className="flex flex-1 flex-col gap-4 p-4 md:gap-8 md:p-8">
        <div className="flex items-center gap-2">
          <HomeIcon className="h-6 w-6" />
          <h1 className="font-headline text-lg font-semibold md:text-2xl">
            Dashboard
          </h1>
        </div>
        <DashboardClient />
      </div>
    </DashboardLayout>
  );
}
