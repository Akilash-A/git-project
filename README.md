# Real-Time Network Packet Monitor

A Next.js application that provides real-time network packet monitoring capabilities similar to Wireshark, with a modern web interface for security analysis and threat detection.

## Features

### 🔄 Real-Time Monitoring
- Live packet capture from network interfaces
- WebSocket-based real-time data streaming
- Support for TCP, UDP, and ICMP protocols
- Automatic packet parsing and analysis

### 🛡️ Security Analysis
- Real-time threat detection and alerting
- Attack pattern recognition (DDoS, Port Scans, Malware, etc.)
- IP whitelisting for trusted sources
- Security event logging and analysis

### 🌐 Network Interface Management
- Multiple network interface support
- Interface selection and configuration
- Real-time interface status monitoring
- Network adapter information display

### 🔍 Advanced Filtering
- IP address filtering
- Port-based filtering
- Protocol-specific monitoring
- Custom filter configurations

### 📊 Dashboard & Analytics
- Real-time packet statistics
- Attack detection metrics
- Interactive packet table with detailed information
- Historical data visualization

## Quick Start

### Development Setup
```bash
# Install all dependencies
npm install
npm run install:server

# Run both frontend and backend
npm run dev:full

# Access the application
# Frontend: http://localhost:3000
# Backend: ws://localhost:3001
```

### Usage
1. **Start Monitoring**: Launch both servers and navigate to http://localhost:3000
2. **Select Interface**: Choose your network interface from the dropdown
3. **Configure Filters**: Set up IP, port, or protocol filters as needed
4. **Begin Monitoring**: Click "Start Monitoring" for real-time packet capture

## Architecture

- **Frontend**: Next.js dashboard with real-time WebSocket connectivity
- **Backend**: Node.js packet capture service with Socket.IO
- **Real-time Data**: Live packet streaming and analysis
- **Security Features**: Threat detection and IP whitelisting

## Security Notice
⚠️ This tool requires network interface access and should only be used for authorized network monitoring. Ensure compliance with local regulations and privacy policies.

For detailed documentation, see the full README sections below.
