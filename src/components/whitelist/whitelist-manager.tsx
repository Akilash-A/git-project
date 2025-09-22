
"use client";

import { useState, useEffect } from "react";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { PlusCircle, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { useToast } from "@/hooks/use-toast";

const ipSchema = z.object({
  ip: z.string().ip({ version: "v4", message: "Invalid IPv4 address" }),
});

const initialWhitelistedIps = ["8.8.8.8", "1.1.1.1"];

export function WhitelistManager() {
  const { toast } = useToast();
  const [whitelistedIps, setWhitelistedIps] = useState<string[]>([]);
  const [isClient, setIsClient] = useState(false);

  useEffect(() => {
    setIsClient(true);
    const storedIps = localStorage.getItem("whitelistedIps");
    if (storedIps) {
      setWhitelistedIps(JSON.parse(storedIps));
    } else {
      setWhitelistedIps(initialWhitelistedIps);
    }
  }, []);

  useEffect(() => {
    if (isClient) {
      localStorage.setItem("whitelistedIps", JSON.stringify(whitelistedIps));
    }
  }, [whitelistedIps, isClient]);

  const form = useForm<z.infer<typeof ipSchema>>({
    resolver: zodResolver(ipSchema),
    defaultValues: {
      ip: "",
    },
  });

  function onSubmit(values: z.infer<typeof ipSchema>) {
    if (whitelistedIps.includes(values.ip)) {
      form.setError("ip", {
        type: "manual",
        message: "IP address already in whitelist.",
      });
      return;
    }
    setWhitelistedIps((prev) => [...prev, values.ip]);
    form.reset();
    toast({
      title: "Success",
      description: `IP address ${values.ip} added to whitelist.`,
    });
  }

  function removeIp(ipToRemove: string) {
    setWhitelistedIps((prev) => prev.filter((ip) => ip !== ipToRemove));
    toast({
      title: "Success",
      description: `IP address ${ipToRemove} removed from whitelist.`,
    });
  }

  if (!isClient) {
    return null;
  }

  return (
    <div className="grid gap-4 md:grid-cols-2 md:gap-8">
      <Card>
        <CardHeader>
          <CardTitle>Add to Whitelist</CardTitle>
          <CardDescription>
            Add an IP address that should not be detected as malicious.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="ip"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>IP Address</FormLabel>
                    <FormControl>
                      <Input placeholder="e.g., 192.168.1.1" {...field} className="border-[hsl(267.1,37.5%,22%)]" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <Button type="submit" className="w-full sm:w-auto">
                <PlusCircle className="mr-2 h-4 w-4" />
                Add IP
              </Button>
            </form>
          </Form>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Whitelisted IPs</CardTitle>
          <CardDescription>
            List of IP addresses exempt from attack detection.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP Address</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {whitelistedIps.length > 0 ? (
                  whitelistedIps.map((ip) => (
                    <TableRow key={ip}>
                      <TableCell className="font-medium">{ip}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => removeIp(ip)}
                        >
                          <Trash2 className="h-4 w-4" />
                          <span className="sr-only">Remove IP</span>
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell
                      colSpan={2}
                      className="h-24 text-center"
                    >
                      No IPs whitelisted.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
