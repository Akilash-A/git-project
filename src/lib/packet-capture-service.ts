import { io, Socket } from 'socket.io-client';
import type { Packet, Alert } from './types';

export interface NetworkInterface {
  name: string;
  address: string;
  netmask: string;
  mac: string;
}

export interface MonitoringOptions {
  protocol?: 'TCP' | 'UDP' | 'ICMP';
  interface?: string;
  filterIp?: string;
  filterPort?: number;
}

export class PacketCaptureService {
  private socket: Socket | null = null;
  private isConnected = false;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;

  constructor(private serverUrl = 'http://localhost:3001') {}

  connect(): Promise<boolean> {
    return new Promise((resolve, reject) => {
      try {
        this.socket = io(this.serverUrl, {
          transports: ['websocket', 'polling'],
          timeout: 10000,
        });

        this.socket.on('connect', () => {
          console.log('Connected to packet monitor server');
          this.isConnected = true;
          this.reconnectAttempts = 0;
          resolve(true);
        });

        this.socket.on('disconnect', () => {
          console.log('Disconnected from packet monitor server');
          this.isConnected = false;
        });

        this.socket.on('connect_error', (error) => {
          console.error('Connection error:', error);
          this.isConnected = false;
          
          if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            setTimeout(() => {
              console.log(`Reconnection attempt ${this.reconnectAttempts}`);
              this.connect();
            }, 2000 * this.reconnectAttempts);
          } else {
            reject(new Error('Failed to connect to packet monitor server'));
          }
        });

        // Set a timeout for initial connection
        setTimeout(() => {
          if (!this.isConnected) {
            reject(new Error('Connection timeout'));
          }
        }, 10000);
      } catch (error) {
        reject(error);
      }
    });
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.isConnected = false;
    }
  }

  startMonitoring(options: MonitoringOptions = {}) {
    if (!this.socket || !this.isConnected) {
      throw new Error('Not connected to packet monitor server');
    }
    this.socket.emit('start-monitoring', options);
  }

  stopMonitoring() {
    if (!this.socket || !this.isConnected) {
      throw new Error('Not connected to packet monitor server');
    }
    this.socket.emit('stop-monitoring');
  }

  onPacket(callback: (data: { packet: Packet; alert: Alert | null }) => void) {
    if (!this.socket) {
      throw new Error('Not connected to packet monitor server');
    }
    this.socket.on('new-packet', callback);
  }

  onNetworkInterfaces(callback: (interfaces: NetworkInterface[]) => void) {
    if (!this.socket) {
      throw new Error('Not connected to packet monitor server');
    }
    this.socket.on('network-interfaces', callback);
  }

  isConnectedToServer(): boolean {
    return this.isConnected;
  }

  // Fallback to mock data if server is not available
  static createMockService(): PacketCaptureService {
    const mockService = new PacketCaptureService();
    
    // Override methods to simulate real behavior
    mockService.connect = async () => {
      console.warn('Using mock packet capture service - server not available');
      return true;
    };

    mockService.startMonitoring = () => {
      console.warn('Mock monitoring started');
    };

    mockService.stopMonitoring = () => {
      console.warn('Mock monitoring stopped');
    };

    mockService.isConnectedToServer = () => false;

    return mockService;
  }
}

// Create a singleton instance
export const packetCaptureService = new PacketCaptureService();