import type { LucideIcon } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface StatsCardProps {
  title: string;
  value: string;
  icon: LucideIcon;
  description: string;
  variant?: "default" | "destructive";
}

export function StatsCard({
  title,
  value,
  icon: Icon,
  description,
  variant = "default",
}: StatsCardProps) {
  return (
    <Card className={cn(variant === "destructive" && "bg-destructive/10 border-destructive/50")}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <Icon className={cn("h-4 w-4 text-muted-foreground", variant === "destructive" && "text-destructive")} />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold font-headline">{value}</div>
        <p className="text-xs text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  );
}
