// Test script to verify packet monitor functionality
const { io } = require('socket.io-client');

console.log('Testing packet monitor connection...');

const socket = io('http://localhost:3001');

socket.on('connect', () => {
  console.log('✅ Connected to packet monitor server');
  
  // Listen for network interfaces
  socket.on('network-interfaces', (interfaces) => {
    console.log('📡 Network interfaces received:', interfaces);
  });
  
  // Listen for packets
  socket.on('new-packet', (data) => {
    console.log('📦 Packet received:', {
      id: data.packet.id,
      sourceIp: data.packet.sourceIp,
      destinationIp: data.packet.destinationIp,
      protocol: data.packet.protocol,
      port: data.packet.port,
      size: data.packet.size,
      direction: data.packet.direction,
      attackType: data.packet.attackType
    });
    
    if (data.alert) {
      console.log('🚨 Alert:', data.alert.message);
    }
  });
  
  // Start monitoring
  console.log('🚀 Starting monitoring...');
  socket.emit('start-monitoring', { interface: 'wlo1' });
  
  // Stop after 30 seconds
  setTimeout(() => {
    console.log('⏹️ Stopping monitoring...');
    socket.emit('stop-monitoring');
    socket.disconnect();
    process.exit(0);
  }, 30000);
});

socket.on('connect_error', (error) => {
  console.error('❌ Connection error:', error);
});

socket.on('disconnect', () => {
  console.log('👋 Disconnected from server');
});