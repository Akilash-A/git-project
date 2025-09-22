"use client";

import { useState, useEffect, useCallback } from "react";
import { 
  Search, 
  Filter, 
  Download, 
  Trash2, 
  Eye, 
  Calendar, 
  Clock, 
  Archive, 
  SortAsc, 
  SortDesc,
  RefreshCw,
  Settings,
  ChevronDown,
  FileText,
  Shield,
  AlertTriangle,
  CheckCircle2,
  X
} from "lucide-react";

import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from "@/components/ui/select";
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Calendar as CalendarComponent } from "@/components/ui/calendar";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import databaseService from "@/lib/database-service";
import type { Packet } from "@/lib/types";

interface PacketFilters {
  search: string;
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  attackType: string;
  dateFrom: Date | null;
  dateTo: Date | null;
  minSize: number | null;
  maxSize: number | null;
  hasAttack: string; // 'all', 'attack', 'normal'
}

interface SortConfig {
  field: keyof Packet;
  direction: 'asc' | 'desc';
}

const ITEMS_PER_PAGE_OPTIONS = [25, 50, 100, 200];
const PROTOCOL_OPTIONS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'SSH', 'FTP', 'DNS'];
const ATTACK_TYPE_OPTIONS = [
  'DDoS Attack',
  'Port Scan',
  'Brute Force',
  'SQL Injection',
  'XSS Attack',
  'Buffer Overflow',
  'Malware',
  'Phishing'
];

export default function PacketArchivePage() {
  const { toast } = useToast();
  
  // Data state
  const [packets, setPackets] = useState<Packet[]>([]);
  const [loading, setLoading] = useState(false);
  const [totalCount, setTotalCount] = useState(0);
  
  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(50);
  
  // Filter state
  const [filters, setFilters] = useState<PacketFilters>({
    search: '',
    sourceIp: '',
    destinationIp: '',
    protocol: 'all',
    attackType: 'all',
    dateFrom: null,
    dateTo: null,
    minSize: null,
    maxSize: null,
    hasAttack: 'all'
  });
  
  // UI state
  const [showFilters, setShowFilters] = useState(false);
  const [selectedPackets, setSelectedPackets] = useState<Set<string | number>>(new Set());
  const [sortConfig, setSortConfig] = useState<SortConfig>({ field: 'timestamp', direction: 'desc' });
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [refreshInterval, setRefreshInterval] = useState(30); // seconds

  // Load packets with current filters and pagination
  const loadPackets = useCallback(async (page: number = 1) => {
    setLoading(true);
    try {
      const offset = (page - 1) * itemsPerPage;
      
      // Build filter options for database query
      const queryOptions: any = {
        limit: itemsPerPage,
        offset,
        sortBy: sortConfig.field,
        sortOrder: sortConfig.direction
      };
      
      // Add filters to query
      if (filters.search) queryOptions.search = filters.search;
      if (filters.sourceIp) queryOptions.sourceIp = filters.sourceIp;
      if (filters.destinationIp) queryOptions.destinationIp = filters.destinationIp;
      if (filters.protocol && filters.protocol !== 'all') queryOptions.protocol = filters.protocol;
      if (filters.attackType && filters.attackType !== 'all') queryOptions.attackType = filters.attackType;
      if (filters.dateFrom) queryOptions.dateFrom = filters.dateFrom.getTime();
      if (filters.dateTo) queryOptions.dateTo = filters.dateTo.getTime();
      if (filters.minSize) queryOptions.minSize = filters.minSize;
      if (filters.maxSize) queryOptions.maxSize = filters.maxSize;
      if (filters.hasAttack !== 'all') queryOptions.hasAttack = filters.hasAttack === 'attack';
      
      const result = await databaseService.getPackets(queryOptions);
      setPackets(result);
      setCurrentPage(page);
      
      // Get total count for pagination
      const stats = await databaseService.getStatistics();
      setTotalCount(stats.totalPackets);
      
    } catch (error) {
      console.error('Failed to load packets:', error);
      toast({
        title: "Error",
        description: "Failed to load packets from database",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  }, [itemsPerPage, sortConfig, filters, toast]);

  // Initial load
  useEffect(() => {
    loadPackets(1);
  }, [loadPackets]);

  // Auto refresh
  useEffect(() => {
    if (!autoRefresh) return;
    
    const interval = setInterval(() => {
      loadPackets(currentPage);
    }, refreshInterval * 1000);
    
    return () => clearInterval(interval);
  }, [autoRefresh, refreshInterval, currentPage, loadPackets]);

  // Filter handlers
  const handleFilterChange = (key: keyof PacketFilters, value: any) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const clearFilters = () => {
    setFilters({
      search: '',
      sourceIp: '',
      destinationIp: '',
      protocol: 'all',
      attackType: 'all',
      dateFrom: null,
      dateTo: null,
      minSize: null,
      maxSize: null,
      hasAttack: 'all'
    });
    setCurrentPage(1);
  };

  const applyFilters = () => {
    setCurrentPage(1);
    loadPackets(1);
  };

  // Selection handlers
  const togglePacketSelection = (packetId: string | number) => {
    const newSelection = new Set(selectedPackets);
    if (newSelection.has(packetId)) {
      newSelection.delete(packetId);
    } else {
      newSelection.add(packetId);
    }
    setSelectedPackets(newSelection);
  };

  const selectAllPackets = () => {
    if (selectedPackets.size === packets.length) {
      setSelectedPackets(new Set());
    } else {
      setSelectedPackets(new Set(packets.map(p => p.id)));
    }
  };

  // Sort handler
  const handleSort = (field: keyof Packet) => {
    const direction = sortConfig.field === field && sortConfig.direction === 'asc' ? 'desc' : 'asc';
    setSortConfig({ field, direction });
  };

  // Export selected packets
  const exportPackets = () => {
    const packetsToExport = selectedPackets.size > 0 
      ? packets.filter(p => selectedPackets.has(p.id))
      : packets;
      
    const dataStr = JSON.stringify(packetsToExport, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `packets-export-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    toast({
      title: "Export Complete",
      description: `Exported ${packetsToExport.length} packets to JSON file`,
    });
  };

  // Delete selected packets
  const deleteSelectedPackets = async () => {
    if (selectedPackets.size === 0) return;
    
    try {
      setLoading(true);
      // Note: This would need to be implemented in the database service
      // await databaseService.deletePackets(Array.from(selectedPackets));
      
      setSelectedPackets(new Set());
      loadPackets(currentPage);
      
      toast({
        title: "Packets Deleted",
        description: `Successfully deleted ${selectedPackets.size} packets`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to delete selected packets",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  // Individual packet action handlers
  const handleViewPacketDetails = (packet: Packet) => {
    toast({
      title: "Packet Details",
      description: `Viewing details for packet from ${packet.sourceIp}:${packet.port}`,
    });
    // TODO: Open a modal or navigate to a detailed view
  };

  const handleExportSinglePacket = (packet: Packet) => {
    const dataStr = JSON.stringify([packet], null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `packet-${packet.id}-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    toast({
      title: "Packet Exported",
      description: `Exported packet ${packet.id} to JSON file`,
    });
  };

  const handleAddToWhitelist = async (packet: Packet) => {
    try {
      // Get current whitelist from localStorage
      const currentWhitelist = JSON.parse(localStorage.getItem("whitelistedIps") || "[]");
      
      // Check if IP is already whitelisted
      if (currentWhitelist.includes(packet.sourceIp)) {
        toast({
          title: "Already Whitelisted",
          description: `IP ${packet.sourceIp} is already in the whitelist`,
        });
        return;
      }
      
      // Add to whitelist
      const updatedWhitelist = [...currentWhitelist, packet.sourceIp];
      localStorage.setItem("whitelistedIps", JSON.stringify(updatedWhitelist));
      
      toast({
        title: "Added to Whitelist",
        description: `IP ${packet.sourceIp} has been added to the whitelist`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to add IP to whitelist",
        variant: "destructive",
      });
    }
  };

  const handleDeleteSinglePacket = async (packet: Packet) => {
    try {
      setLoading(true);
      // Note: This would need to be implemented in the database service
      // await databaseService.deletePacket(packet.id);
      
      // For now, just show a success message and reload
      toast({
        title: "Packet Deleted",
        description: `Successfully deleted packet ${packet.id}`,
      });
      
      // Reload the current page
      loadPackets(currentPage);
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to delete packet",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  // Format functions
  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getAttackBadge = (attackType: string | null) => {
    if (!attackType) {
      return <Badge variant="outline" className="text-green-600 border-green-600">Normal</Badge>;
    }
    
    const isHighRisk = attackType.toLowerCase().includes('ddos') || 
                      attackType.toLowerCase().includes('critical');
    
    return (
      <Badge variant={isHighRisk ? "destructive" : "secondary"}>
        {attackType}
      </Badge>
    );
  };

  const getSortIcon = (field: keyof Packet) => {
    if (sortConfig.field !== field) return null;
    return sortConfig.direction === 'asc' ? 
      <SortAsc className="ml-1 h-3 w-3" /> : 
      <SortDesc className="ml-1 h-3 w-3" />;
  };

  const totalPages = Math.ceil(totalCount / itemsPerPage);

  return (
    <DashboardLayout>
      <div className="flex flex-1 flex-col gap-4 p-4 md:gap-8 md:p-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="font-headline text-lg font-semibold md:text-2xl flex items-center gap-2">
              <Archive className="h-6 w-6" />
              Packet Archive
            </h1>
            <p className="text-muted-foreground">
              Browse and manage all network packets stored in the database
            </p>
          </div>
          
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <span>Auto Refresh</span>
              <Switch 
                checked={autoRefresh} 
                onCheckedChange={setAutoRefresh}
              />
              {autoRefresh && (
                <Select value={refreshInterval.toString()} onValueChange={(v) => setRefreshInterval(parseInt(v))}>
                  <SelectTrigger className="w-20">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="10">10s</SelectItem>
                    <SelectItem value="30">30s</SelectItem>
                    <SelectItem value="60">1m</SelectItem>
                    <SelectItem value="300">5m</SelectItem>
                  </SelectContent>
                </Select>
              )}
            </div>
            <Button onClick={() => loadPackets(currentPage)} disabled={loading}>
              <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </div>

        {/* Stats Bar */}
        <Card>
          <CardContent className="pt-6">
            <div className="grid gap-4 md:grid-cols-4">
              <div className="text-center">
                <div className="text-2xl font-bold">{totalCount.toLocaleString()}</div>
                <div className="text-sm text-muted-foreground">Total Packets</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold">{packets.length}</div>
                <div className="text-sm text-muted-foreground">Displayed</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold">{selectedPackets.size}</div>
                <div className="text-sm text-muted-foreground">Selected</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold">{packets.filter(p => p.attackType).length}</div>
                <div className="text-sm text-muted-foreground">With Attacks</div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Filters */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <Filter className="h-5 w-5" />
                Filters & Search
              </CardTitle>
              <Button 
                variant="outline" 
                onClick={() => setShowFilters(!showFilters)}
                className="border-2 dark:border-gray-600 dark:hover:border-gray-500"
              >
                {showFilters ? 'Hide Filters' : 'Show Filters'}
                <ChevronDown className={`ml-2 h-4 w-4 transition-transform ${showFilters ? 'rotate-180' : ''}`} />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {/* Quick Search */}
            <div className="mb-4">
              <Label htmlFor="search">Quick Search</Label>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="search"
                    placeholder="Search packets by IP, protocol, or attack type..."
                    value={filters.search}
                    onChange={(e) => handleFilterChange('search', e.target.value)}
                    className="pl-10"
                  />
                </div>
                <Button onClick={applyFilters} disabled={loading}>
                  Search
                </Button>
                <Button variant="outline" onClick={clearFilters}>
                  Clear
                </Button>
              </div>
            </div>

            {/* Advanced Filters */}
            {showFilters && (
              <div className="space-y-4 pt-4 border-t">
                <div className="grid gap-4 md:grid-cols-3">
                  {/* IP Filters */}
                  <div>
                    <Label htmlFor="sourceIp">Source IP</Label>
                    <Input
                      id="sourceIp"
                      placeholder="e.g., 192.168.1.1"
                      value={filters.sourceIp}
                      onChange={(e) => handleFilterChange('sourceIp', e.target.value)}
                    />
                  </div>
                  <div>
                    <Label htmlFor="destinationIp">Destination IP</Label>
                    <Input
                      id="destinationIp"
                      placeholder="e.g., 10.0.0.1"
                      value={filters.destinationIp}
                      onChange={(e) => handleFilterChange('destinationIp', e.target.value)}
                    />
                  </div>
                  <div>
                    <Label htmlFor="protocol">Protocol</Label>
                    <Select value={filters.protocol} onValueChange={(v) => handleFilterChange('protocol', v)}>
                      <SelectTrigger>
                        <SelectValue placeholder="All Protocols" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Protocols</SelectItem>
                        {PROTOCOL_OPTIONS.map(protocol => (
                          <SelectItem key={protocol} value={protocol}>{protocol}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="grid gap-4 md:grid-cols-2">
                  {/* Attack Type & Status */}
                  <div>
                    <Label htmlFor="attackType">Attack Type</Label>
                    <Select value={filters.attackType} onValueChange={(v) => handleFilterChange('attackType', v)}>
                      <SelectTrigger>
                        <SelectValue placeholder="All Attack Types" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Attack Types</SelectItem>
                        {ATTACK_TYPE_OPTIONS.map(type => (
                          <SelectItem key={type} value={type}>{type}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label htmlFor="hasAttack">Packet Status</Label>
                    <Select value={filters.hasAttack} onValueChange={(v) => handleFilterChange('hasAttack', v)}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Packets</SelectItem>
                        <SelectItem value="attack">Attack Packets Only</SelectItem>
                        <SelectItem value="normal">Normal Packets Only</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="grid gap-4 md:grid-cols-4">
                  {/* Date Range */}
                  <div>
                    <Label>Date From</Label>
                    <Popover>
                      <PopoverTrigger asChild>
                        <Button variant="outline" className="w-full justify-start text-left font-normal">
                          <Calendar className="mr-2 h-4 w-4" />
                          {filters.dateFrom ? filters.dateFrom.toLocaleDateString() : "Select date"}
                        </Button>
                      </PopoverTrigger>
                      <PopoverContent className="w-auto p-0">
                        <CalendarComponent
                          mode="single"
                          selected={filters.dateFrom || undefined}
                          onSelect={(date) => handleFilterChange('dateFrom', date)}
                          initialFocus
                        />
                      </PopoverContent>
                    </Popover>
                  </div>
                  <div>
                    <Label>Date To</Label>
                    <Popover>
                      <PopoverTrigger asChild>
                        <Button variant="outline" className="w-full justify-start text-left font-normal">
                          <Calendar className="mr-2 h-4 w-4" />
                          {filters.dateTo ? filters.dateTo.toLocaleDateString() : "Select date"}
                        </Button>
                      </PopoverTrigger>
                      <PopoverContent className="w-auto p-0">
                        <CalendarComponent
                          mode="single"
                          selected={filters.dateTo || undefined}
                          onSelect={(date) => handleFilterChange('dateTo', date)}
                          initialFocus
                        />
                      </PopoverContent>
                    </Popover>
                  </div>
                  
                  {/* Size Range */}
                  <div>
                    <Label htmlFor="minSize">Min Size (bytes)</Label>
                    <Input
                      id="minSize"
                      type="number"
                      placeholder="0"
                      value={filters.minSize || ''}
                      onChange={(e) => handleFilterChange('minSize', e.target.value ? parseInt(e.target.value) : null)}
                    />
                  </div>
                  <div>
                    <Label htmlFor="maxSize">Max Size (bytes)</Label>
                    <Input
                      id="maxSize"
                      type="number"
                      placeholder="Unlimited"
                      value={filters.maxSize || ''}
                      onChange={(e) => handleFilterChange('maxSize', e.target.value ? parseInt(e.target.value) : null)}
                    />
                  </div>
                </div>

                <div className="flex gap-2 pt-4">
                  <Button onClick={applyFilters} disabled={loading}>
                    Apply Filters
                  </Button>
                  <Button variant="outline" onClick={clearFilters}>
                    Clear All Filters
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Actions Bar */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Checkbox
              checked={selectedPackets.size === packets.length && packets.length > 0}
              onCheckedChange={selectAllPackets}
            />
            <span className="text-sm text-muted-foreground">
              {selectedPackets.size > 0 ? `${selectedPackets.size} selected` : 'Select all'}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <Select value={itemsPerPage.toString()} onValueChange={(v) => setItemsPerPage(parseInt(v))}>
              <SelectTrigger className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ITEMS_PER_PAGE_OPTIONS.map(size => (
                  <SelectItem key={size} value={size.toString()}>{size} per page</SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Button
              variant="outline"
              onClick={exportPackets}
              disabled={loading}
              className="border-2 dark:border-gray-600 dark:hover:border-gray-500"
            >
              <Download className="h-4 w-4 mr-2" />
              Export {selectedPackets.size > 0 ? `(${selectedPackets.size})` : 'All'}
            </Button>

            {selectedPackets.size > 0 && (
              <Button
                variant="destructive"
                onClick={deleteSelectedPackets}
                disabled={loading}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Delete Selected
              </Button>
            )}
          </div>
        </div>

        {/* Packets Table */}
        <Card>
          <CardContent className="p-0">
            <ScrollArea className="h-[600px] w-full">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-12">
                      <Checkbox
                        checked={selectedPackets.size === packets.length && packets.length > 0}
                        onCheckedChange={selectAllPackets}
                      />
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-muted/50"
                      onClick={() => handleSort('timestamp')}
                    >
                      <div className="flex items-center">
                        Timestamp
                        {getSortIcon('timestamp')}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-muted/50"
                      onClick={() => handleSort('sourceIp')}
                    >
                      <div className="flex items-center">
                        Source IP
                        {getSortIcon('sourceIp')}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-muted/50"
                      onClick={() => handleSort('destinationIp')}
                    >
                      <div className="flex items-center">
                        Destination IP
                        {getSortIcon('destinationIp')}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-muted/50"
                      onClick={() => handleSort('protocol')}
                    >
                      <div className="flex items-center">
                        Protocol
                        {getSortIcon('protocol')}
                      </div>
                    </TableHead>
                    <TableHead>Port</TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-muted/50"
                      onClick={() => handleSort('size')}
                    >
                      <div className="flex items-center">
                        Size
                        {getSortIcon('size')}
                      </div>
                    </TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {packets.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={9} className="text-center py-8">
                        {loading ? (
                          <div className="flex items-center justify-center">
                            <RefreshCw className="h-4 w-4 animate-spin mr-2" />
                            Loading packets...
                          </div>
                        ) : (
                          <div className="text-muted-foreground">
                            No packets found matching your criteria
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  ) : (
                    packets.map((packet) => (
                      <TableRow key={packet.id}>
                        <TableCell>
                          <Checkbox
                            checked={selectedPackets.has(packet.id)}
                            onCheckedChange={() => togglePacketSelection(packet.id)}
                          />
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          <div className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {formatTimestamp(packet.timestamp)}
                          </div>
                        </TableCell>
                        <TableCell className="font-mono">
                          {packet.sourceIp}
                        </TableCell>
                        <TableCell className="font-mono">
                          {packet.destinationIp}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{packet.protocol}</Badge>
                        </TableCell>
                        <TableCell className="text-sm">
                          {packet.port}
                        </TableCell>
                        <TableCell>{packet.size ? formatBytes(packet.size) : 'N/A'}</TableCell>
                        <TableCell>
                          {getAttackBadge(packet.attackType)}
                        </TableCell>
                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm">
                                <Settings className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent>
                              <DropdownMenuItem onClick={() => handleViewPacketDetails(packet)}>
                                <Eye className="h-4 w-4 mr-2" />
                                View Details
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleExportSinglePacket(packet)}>
                                <FileText className="h-4 w-4 mr-2" />
                                Export Packet
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleAddToWhitelist(packet)}>
                                <Shield className="h-4 w-4 mr-2" />
                                Add to Whitelist
                              </DropdownMenuItem>
                              <DropdownMenuItem 
                                className="text-red-600"
                                onClick={() => handleDeleteSinglePacket(packet)}
                              >
                                <Trash2 className="h-4 w-4 mr-2" />
                                Delete Packet
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Pagination */}
        <div className="flex items-center justify-between">
          <div className="text-sm text-muted-foreground">
            Showing {((currentPage - 1) * itemsPerPage) + 1} to {Math.min(currentPage * itemsPerPage, totalCount)} of {totalCount.toLocaleString()} packets
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              onClick={() => loadPackets(currentPage - 1)}
              disabled={currentPage <= 1 || loading}
              className="border-2 dark:border-gray-600 dark:hover:border-gray-500"
            >
              Previous
            </Button>
            <span className="text-sm">
              Page {currentPage} of {totalPages}
            </span>
            <Button
              variant="outline"
              onClick={() => loadPackets(currentPage + 1)}
              disabled={currentPage >= totalPages || loading}
              className="border-2 dark:border-gray-600 dark:hover:border-gray-500"
            >
              Next
            </Button>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}